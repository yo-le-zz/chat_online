import os
import psycopg2 as SQL
import colorama
import threading
import time
import bcrypt
import json
import hashlib
from dotenv import load_dotenv
from cryptography.fernet import Fernet

colorama.init(autoreset=True)

# -------Configuration-------
load_dotenv()
stop_threads = False
database = os.getenv('DATABASE')
host = os.getenv('IP_SERVEUR')
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
port = os.getenv('PORT')
# ---------------------------

# ------------------- CRYPTO / HASH -------------------
# Fernet key (persistée dans chat.key)
KEY_PATH = os.path.join(os.path.dirname(__file__), "chat.key")
try:
    with open(KEY_PATH, "rb") as kf:
        key = kf.read()
except Exception:
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as kf:
        kf.write(key)
fernet = Fernet(key)


def encrypt_text(text: str) -> bytes:
    if text is None:
        return None
    try:
        return fernet.encrypt(text.encode("utf-8"))
    except Exception as e:
        print(colorama.Fore.RED + f"Erreur encrypt_text: {e}")
        return None


def decrypt_text(token) -> str:
    if token is None:
        return None
    try:
        # token from DB can be memoryview / bytes
        if isinstance(token, memoryview):
            token = bytes(token)
        return fernet.decrypt(token).decode("utf-8")
    except Exception as e:
        print(colorama.Fore.RED + f"Erreur decrypt_text: {e}")
        return None


def encrypt_json(obj) -> bytes:
    try:
        return encrypt_text(json.dumps(obj, ensure_ascii=False))
    except Exception as e:
        print(colorama.Fore.RED + f"Erreur encrypt_json: {e}")
        return None


def decrypt_json(token):
    if token is None:
        return []
    try:
        txt = decrypt_text(token)
        return json.loads(txt) if txt else []
    except Exception as e:
        print(colorama.Fore.RED + f"Erreur decrypt_json: {e}")
        return []


def hash_text_bcrypt(text: str) -> bytes:
    """Hash avec bcrypt (pour pseudo, mot de passe, status, message-hash if needed)"""
    if text is None:
        return None
    try:
        return bcrypt.hashpw(text.encode("utf-8"), bcrypt.gensalt())
    except Exception as e:
        print(colorama.Fore.RED + f"Erreur hash_text_bcrypt: {e}")
        return None


def verify_hash(text: str, hashed) -> bool:
    """Compare texte en clair avec hash bcrypt (hashed peut être bytes ou memoryview)"""
    if text is None or hashed is None:
        return False
    try:
        if isinstance(hashed, memoryview):
            hashed = bytes(hashed)
        return bcrypt.checkpw(text.encode("utf-8"), hashed)
    except Exception as e:
        print(colorama.Fore.RED + f"Erreur verify_hash: {e}")
        return False


# ------------------ DATABASE ------------------
def connect_to_db(host, database, user, password, port):
    try:
        connection = SQL.connect(
            host=str(host),
            database=str(database),
            user=str(user),
            password=str(password),
            port=str(port),
            client_encoding="UTF8",
        )
        print(colorama.Fore.GREEN + "Connexion à la base de données réussie.")
        return connection
    except SQL.Error as e:
        print(colorama.Fore.RED + f"Erreur de connexion: {e}")
        return None


def close_connection(connection):
    if connection:
        connection.close()
        print(colorama.Fore.YELLOW + "Connexion fermée.")


def exists_table(connection, name):
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = %s
                );
            """,
                (name,),
            )
            return cursor.fetchone()[0]
    except SQL.Error as e:
        print(colorama.Fore.RED + f"Erreur vérification table: {e}")
        return False


# ------------------ HELPERS ------------------
def get_user_row_by_pseudo(cursor, pseudo_plain):
    """Retourne la ligne DB (row) de l'utilisateur correspondant au pseudo (plaintext).
       Comme bcrypt est salé, on parcourt les pseudo_hash et on vérifie avec bcrypt.checkpw.
       Retourne la row complète si trouvée, sinon None.
    """
    try:
        cursor.execute("SELECT id, pseudo_hash, password, Role, friendlist, Created_At FROM users")
        rows = cursor.fetchall()
        for row in rows:
            stored_pseudo_hash = row[1]
            if verify_hash(pseudo_plain, stored_pseudo_hash):
                return row  # id, pseudo_hash, password, Role, friendlist, Created_At
        return None
    except Exception as e:
        print(colorama.Fore.RED + f"Erreur get_user_row_by_pseudo: {e}")
        return None


def load_friendlist_from_db(cursor, user_id):
    cursor.execute("SELECT friendlist FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    if not row or row[0] is None:
        return []
    return decrypt_json(row[0])


def save_friendlist_to_db(cursor, user_id, friendlist):
    cursor.execute("UPDATE users SET friendlist = %s WHERE id = %s", (encrypt_json(friendlist), user_id))


# ------------------ THREAD FUNCTIONS ------------------
def receive_messages(user_id, ami_id, stop_event):
    last_checked = None
    while not stop_event.is_set():
        try:
            with connection.cursor() as cursor:
                if last_checked:
                    cursor.execute(
                        """
                        SELECT sender_id, content, Created_At FROM messages
                        WHERE sender_id = %s AND receiver_id = %s AND Created_At > %s
                        ORDER BY Created_At ASC
                    """,
                        (ami_id, user_id, last_checked),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT sender_id, content, Created_At FROM messages
                        WHERE sender_id = %s AND receiver_id = %s
                        ORDER BY CREATED_AT ASC
                    """,
                        (ami_id, user_id),
                    )

                new_messages = cursor.fetchall()
                for sender_id, content, created_at in new_messages:
                    try:
                        plain = decrypt_text(content)
                    except Exception:
                        plain = "<message illisible>"
                    ts = created_at.strftime("%H:%M:%S") if hasattr(created_at, "strftime") else str(created_at)
                    print(colorama.Fore.CYAN + f"\n[{ts}] {plain}")

                if new_messages:
                    last_checked = new_messages[-1][2]
        except Exception as e:
            print(colorama.Fore.RED + f"Erreur dans receive_messages: {e}")
            try:
                connection.rollback()
            except Exception:
                pass

        time.sleep(1)


def check_friend_requests(user_id):
    """Fonction lancée côté receiver (utilise global user pour pseudo en clair)."""
    global stop_threads, user
    while not stop_threads:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id, sender_id, receiver_id, sender_name, status_hash FROM friend_requests WHERE receiver_id = %s", (user_id,))
                requests = cursor.fetchall()
                for req in requests:
                    req_id, sender_id, receiver_id, sender_name, status_hash = req
                    # si statut 'pending'
                    if status_hash and verify_hash("pending", status_hash):
                        # on affiche le sender_name (stocké au moment de la requête)
                        display_name = sender_name if sender_name else "Utilisateur inconnu"
                        print(colorama.Fore.CYAN + f"Nouvelle demande d'ami de: {display_name}")
                        accept = input(colorama.Fore.CYAN + "Accepter la demande ? (o/n): ")
                        new_status = "accepted" if accept.lower() == "o" else "rejected"
                        new_status_hash = hash_text_bcrypt(new_status)
                        # mettre à jour status_hash et (optionnel) status chiffré
                        enc_status = encrypt_text(new_status)
                        cursor.execute("UPDATE friend_requests SET status = %s, status_hash = %s WHERE id = %s", (enc_status, new_status_hash, req_id))

                        # si accepted, mettre à jour friendlists des deux utilisateurs
                        if new_status == "accepted":
                            # ajouter receiver (current user) au friendlist du sender
                            cursor.execute("SELECT friendlist FROM users WHERE id = %s", (sender_id,))
                            sender_fl_row = cursor.fetchone()
                            sender_fl = decrypt_json(sender_fl_row[0]) if sender_fl_row and sender_fl_row[0] else []
                            if user["pseudo"] not in sender_fl:
                                sender_fl.append(user["pseudo"])
                                cursor.execute("UPDATE users SET friendlist = %s WHERE id = %s", (encrypt_json(sender_fl), sender_id))

                            # ajouter sender_name au friendlist du receiver (local user)
                            receiver_fl = user.get("Friendlist", [])
                            if display_name not in receiver_fl:
                                receiver_fl.append(display_name)
                                user["Friendlist"] = receiver_fl
                                cursor.execute("UPDATE users SET friendlist = %s WHERE id = %s", (encrypt_json(receiver_fl), receiver_id))

                        connection.commit()
                        print(colorama.Fore.GREEN + ("Demande acceptée." if new_status == "accepted" else "Demande rejetée."))
        except Exception as e:
            print(colorama.Fore.RED + f"Erreur dans check_friend_requests: {e}")
            try:
                connection.rollback()
            except Exception:
                pass
        time.sleep(5)


def verifier_si_un_ami_a_supprimer_son_compte(Friendlist, user, ID):
    global stop_threads
    while not stop_threads:
        try:
            updated_friendlist = []
            with connection.cursor() as cursor:
                for friend in Friendlist[:]:
                    # Parcourir tous les utilisateurs pour trouver le pseudo
                    cursor.execute("SELECT id, pseudo_hash, friendlist FROM users")
                    rows = cursor.fetchall()
                    friend_found = False
                    for uid, pseudo_hash, friendlist_enc in rows:
                        if verify_hash(friend, pseudo_hash):
                            friend_found = True
                            # Vérifier que l'ami nous a encore dans sa friendlist
                            friend_fl = decrypt_json(friendlist_enc) if friendlist_enc else []
                            if user["pseudo"] in friend_fl:
                                updated_friendlist.append(friend)
                            else:
                                print(colorama.Fore.YELLOW + f"L'ami '{friend}' vous a supprimé de sa liste.")
                            break
                    if not friend_found:
                        print(colorama.Fore.YELLOW + f"L'ami '{friend}' a supprimé son compte.")
                # Mettre à jour uniquement si nécessaire
                if set(updated_friendlist) != set(Friendlist):
                    Friendlist[:] = updated_friendlist
                    save_friendlist_to_db(cursor, ID, Friendlist)
                    cursor.connection.commit()
        except Exception as e:
            print(colorama.Fore.RED + f"Erreur verifier_si_un_ami_a_supprimer_son_compte: {e}")
            try:
                connection.rollback()
            except Exception:
                pass
        time.sleep(10)



def friend_request_listener(demande_ID):
    """Thread côté sender : attend la mise à jour du status et met à jour friendlist."""
    global stop_threads, user
    handled = False
    while not stop_threads and not handled:
        try:
            with connection.cursor() as cursor:
                # récupérer la requête
                cursor.execute(
                    "SELECT sender_id, receiver_id, sender_name, status_hash FROM friend_requests WHERE id = %s",
                    (demande_ID,)
                )
                status_data = cursor.fetchone()
                if not status_data:
                    time.sleep(2)
                    continue

                sender_id, receiver_id, sender_name, status_hash = status_data

                # vérifier si accepté
                if status_hash and verify_hash("accepted", status_hash):
                    print(colorama.Fore.GREEN + f"\nVotre demande d'ami a été acceptée par {sender_name} !\n")
                    # mettre à jour la friendlist locale
                    with connection.cursor() as cur2:
                        cur2.execute("SELECT friendlist FROM users WHERE id = %s", (user["ID"],))
                        row = cur2.fetchone()
                        user["Friendlist"] = decrypt_json(row[0]) if row and row[0] else []
                    handled = True

                # vérifier si rejeté
                elif status_hash and verify_hash("rejected", status_hash):
                    print(colorama.Fore.RED + f"\nVotre demande d'ami a été rejetée par {sender_name}.\n")
                    handled = True

        except Exception as e:
            print(colorama.Fore.RED + f"Erreur dans friend_request_listener: {e}")
            try:
                connection.rollback()
            except Exception:
                pass

        time.sleep(2)



# ------------------ USER FUNCTIONS ------------------
def connect_user(pseudo, password, ID, Friendlist, Role, Created_At):
    global user
    user = {
        "pseudo": pseudo,
        "password": password,
        "ID": ID,
        "Friendlist": Friendlist,
        "Role": Role,
        "Created_At": Created_At,
    }
    print(colorama.Fore.GREEN + f"Utilisateur connecté: {pseudo}, avec le rôle: {Role}")

    threading.Thread(target=verifier_si_un_ami_a_supprimer_son_compte, args=(Friendlist, user, ID), daemon=True).start()
    threading.Thread(target=check_friend_requests, args=(ID,), daemon=True).start()
    # check_friend_status referenced elsewhere; ensure it exists if used
    # threading.Thread(target=check_friend_status, args=(user,), daemon=True).start()

    while True:
        print(colorama.Fore.CYAN + f"=== Comptes de l'{Role} : {pseudo} ===")
        print(colorama.Fore.CYAN + "1. Voir les informations du compte")
        print(colorama.Fore.CYAN + "2. Modifier les informations du compte")
        print(colorama.Fore.CYAN + "3. Ajouter un ami")
        print(colorama.Fore.CYAN + "4. Supprimer un ami")
        print(colorama.Fore.CYAN + "5. Accéder à la liste d'amis")
        print(colorama.Fore.CYAN + "6. Accéder au chat")
        if Role == "admin":
            print(colorama.Fore.YELLOW + "7. Accéder au panneau d'administration")
            print(colorama.Fore.CYAN + "8. Se déconnecter")
            print(colorama.Fore.CYAN + "9. Quitter")
        else:
            print(colorama.Fore.CYAN + "7. Se déconnecter")
            print(colorama.Fore.CYAN + "8. Supprimer le compte")
            print(colorama.Fore.CYAN + "9. Quitter")
        choice = input(colorama.Fore.CYAN + "Choisissez une option: ")

        if choice == "1":
            view_account_info(user)
        elif choice == "2":
            modify_account_info(user)
        elif choice == "3":
            add_friend(user)
        elif choice == "4":
            delete_friend(user)
        elif choice == "5":
            access_friend_list(user)
        elif choice == "6":
            chat(user)
        elif choice == "7" and Role == "admin":
            admin_panel()
        elif choice == "7" and Role == "user":
            menu()
        elif choice == "8" and Role == "admin":
            menu()
        elif choice == "8" and Role == "user":
            del_compte(user)
            break
        elif choice == "9":
            quit_program()
        else:
            print(colorama.Fore.RED + "Option invalide.")
    menu()


def chat(user):
    if not user["Friendlist"]:
        print(colorama.Fore.MAGENTA + "Tu n’as encore aucun ami.")
        return

    print("=== Chat avec tes amis ===")
    for i, ami in enumerate(user["Friendlist"], start=1):
        print(colorama.Fore.CYAN + f"{i}. {ami}")

    choix = input(colorama.Fore.CYAN + "Tape le numéro de l'ami avec qui tu veux discuter: ")
    if not choix.isdigit():
        print(colorama.Fore.RED + "Erreur : tu dois entrer un numéro.")
        return

    index = int(choix) - 1
    if index < 0 or index >= len(user["Friendlist"]):
        print(colorama.Fore.RED + "Erreur : numéro invalide.")
        return

    ami_choisi = user["Friendlist"][index]

    with connection.cursor() as cursor:
        # on recherche par pseudo_hash (bcrypt stored)
        cursor.execute("SELECT id FROM users")
        rows = cursor.fetchall()
        ami_id = None
        for (uid,) in rows:
            cursor.execute("SELECT pseudo_hash FROM users WHERE id = %s", (uid,))
            h = cursor.fetchone()[0]
            if verify_hash(ami_choisi, h):
                ami_id = uid
                break

        if not ami_id:
            print(colorama.Fore.RED + "Utilisateur introuvable.")
            return

        cursor.execute(
            """
            SELECT sender_id, content, Created_At FROM messages
            WHERE (sender_id = %s AND receiver_id = %s)
               OR (sender_id = %s AND receiver_id = %s)
            ORDER BY Created_At ASC
            """,
            (user["ID"], ami_id, ami_id, user["ID"]),
        )
        messages = cursor.fetchall()

        print(colorama.Fore.MAGENTA + f"=== Conversation avec {ami_choisi} ===")
        for sender_id, content, date in messages:
            sender_name = user["pseudo"] if sender_id == user["ID"] else ami_choisi
            try:
                plain = decrypt_text(content)
            except Exception:
                plain = "<message illisible>"
            print(colorama.Fore.CYAN + f"[{date}] {sender_name}: {plain}")

    stop_chat_event = threading.Event()
    thread_reception = threading.Thread(target=receive_messages, args=(user["ID"], ami_id, stop_chat_event), daemon=True)
    thread_reception.start()

    while True:
        message = input(colorama.Fore.CYAN + "Entrer un message (ou 'exit') : ").strip()
        if message.lower() == "exit":
            print(colorama.Fore.YELLOW + "Fin du chat.")
            stop_chat_event.set()
            thread_reception.join()
            break

        if not message:
            print(colorama.Fore.RED + "Erreur : le message ne peut pas être vide.")
            continue

        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO messages (sender_id, receiver_id, content)
                VALUES (%s, %s, %s)
                """,
                (user["ID"], ami_id, encrypt_text(message)),
            )
            connection.commit()

        print(colorama.Fore.MAGENTA + f"[{user['pseudo']}] {message}")


def delete_friend(user):
    print(colorama.Fore.CYAN + "=== Supprimer un ami ===")
    friend_pseudo = input(colorama.Fore.CYAN + "Entrez le pseudo de l'ami à supprimer: ")

    if friend_pseudo not in user["Friendlist"]:
        print(colorama.Fore.RED + f"Aucun ami trouvé avec le pseudo: {friend_pseudo}.")
        return

    with connection.cursor() as cursor:
        # Supprimer de la friendlist locale
        try:
            user["Friendlist"].remove(friend_pseudo)
        except ValueError:
            pass
        save_friendlist_to_db(cursor, user["ID"], user["Friendlist"])

        # Récupérer l'ID et la friendlist de l'ami via pseudo_hash
        cursor.execute("SELECT id, pseudo_hash, friendlist FROM users")
        rows = cursor.fetchall()

        for uid, pseudo_hash_db, fl_enc in rows:
            if verify_hash(friend_pseudo, pseudo_hash_db):
                # Retirer l'utilisateur actuel de la friendlist de l'ami
                friend_list = decrypt_json(fl_enc) or []
                if user["pseudo"] in friend_list:
                    friend_list.remove(user["pseudo"])
                    save_friendlist_to_db(cursor, uid, friend_list)

                # Supprimer les éventuelles demandes d'ami entre les deux
                cursor.execute(
                    """
                    DELETE FROM friend_requests
                    WHERE (sender_id = %s AND receiver_id = %s)
                       OR (sender_id = %s AND receiver_id = %s)
                    """,
                    (user["ID"], uid, uid, user["ID"]),
                )

                # Supprimer tous les messages échangés
                cursor.execute(
                    """
                    DELETE FROM messages
                    WHERE (sender_id = %s AND receiver_id = %s)
                       OR (sender_id = %s AND receiver_id = %s)
                    """,
                    (user["ID"], uid, uid, user["ID"]),
                )

                break

        connection.commit()

    print(colorama.Fore.GREEN + f"Ami '{friend_pseudo}' supprimé avec succès, et messages supprimés.")



def add_friend(user):
    print(colorama.Fore.CYAN + "=== Ajouter un ami ===")
    friend_pseudo = input(colorama.Fore.CYAN + "Entrez le pseudo de l'ami à ajouter: ")
    if friend_pseudo == user["pseudo"]:
        print(colorama.Fore.RED + "Vous ne pouvez pas vous ajouter vous-même!")
        return

    with connection.cursor() as cursor:
        cursor.execute("SELECT id, pseudo_hash FROM users")
        rows = cursor.fetchall()

        friend_id = None
        for uid, hashed_pseudo in rows:
            if verify_hash(friend_pseudo, hashed_pseudo):
                friend_id = uid
                break

        if friend_id:
            status = "pending"
            status_hash = hash_text_bcrypt(status)
            enc_status = encrypt_text(status)
            sender_name = user["pseudo"]
            cursor.execute(
                "INSERT INTO friend_requests (sender_id, receiver_id, sender_name, status, status_hash) VALUES (%s, %s, %s, %s, %s)",
                (user["ID"], friend_id, sender_name, enc_status, status_hash),
            )
            connection.commit()
            cursor.execute(
                "SELECT id FROM friend_requests WHERE sender_id = %s AND receiver_id = %s ORDER BY Created_At DESC LIMIT 1",
                (user["ID"], friend_id),
            )
            demande_id = cursor.fetchone()
            if demande_id:
                threading.Thread(target=friend_request_listener, args=(demande_id[0],), daemon=True).start()
            print(colorama.Fore.GREEN + f"Demande d'ami envoyée à {friend_pseudo}.")
        else:
            print(colorama.Fore.RED + f"Aucun utilisateur trouvé avec le pseudo: {friend_pseudo}.")


def del_compte(user):
    print(colorama.Fore.RED + "=== Suppression du compte ===")
    confirmation = input(colorama.Fore.RED + "Tapez 'OUI' pour confirmer la suppression: ")
    if confirmation != "OUI":
        print(colorama.Fore.YELLOW + "Suppression annulée.")
        return
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, friendlist FROM users")
        users_with_friend = cursor.fetchall()
        for u_id, fl_enc in users_with_friend:
            fl = decrypt_json(fl_enc) or []
            if fl and user["pseudo"] in fl:
                fl.remove(user["pseudo"])
                save_friendlist_to_db(cursor, u_id, fl)
        cursor.execute("DELETE FROM friend_requests WHERE sender_id = %s OR receiver_id = %s", (user["ID"], user["ID"]))
        cursor.execute("DELETE FROM users WHERE id = %s", (user["ID"],))
        connection.commit()
    print(colorama.Fore.GREEN + "Compte supprimé avec succès.")


def view_account_info(user):
    print(colorama.Fore.MAGENTA + f"=== Infos compte {user['pseudo']} ===")
    print(colorama.Fore.MAGENTA + f"ID: {user['ID']}")
    print(colorama.Fore.MAGENTA + f"Pseudo: {user['pseudo']}")
    # password is stored as bcrypt bytes
    hashed_password_bytes = user["password"] if isinstance(user["password"], (bytes, bytearray)) else bytes(user["password"])
    print(colorama.Fore.MAGENTA + f"Mot de passe (hashé): {hashed_password_bytes.hex()}")
    print(colorama.Fore.MAGENTA + f"Role: {user['Role']}")
    print(colorama.Fore.MAGENTA + f"Date de création: {user['Created_At']}")


def modify_account_info(user):
    print(colorama.Fore.CYAN + "=== Modifier le compte ===")
    print(colorama.Fore.CYAN + "1. Modifier le pseudo")
    print(colorama.Fore.CYAN + "2. Modifier le mot de passe")
    choice = input(colorama.Fore.CYAN + "Choisissez: ")
    with connection.cursor() as cursor:
        if choice == "1":
            new_pseudo = input(colorama.Fore.CYAN + "Nouveau pseudo: ")
            if len(new_pseudo) >= 3:
                # vérifier unicité en parcourant les pseudo_hash
                cursor.execute("SELECT pseudo_hash FROM users")
                existing = cursor.fetchall()
                for (h,) in existing:
                    if verify_hash(new_pseudo, h):
                        print(colorama.Fore.RED + "Ce pseudo est déjà utilisé.")
                        return
                old_pseudo = user["pseudo"]
                # mettre à jour pseudo_hash (bcrypt) et friendlists
                new_pseudo_hash = hash_text_bcrypt(new_pseudo)
                cursor.execute("UPDATE users SET pseudo_hash = %s WHERE id = %s", (new_pseudo_hash, user["ID"]))
                cursor.execute("SELECT id, friendlist FROM users")
                all_users = cursor.fetchall()
                for u_id, fl_enc in all_users:
                    fl = decrypt_json(fl_enc) or []
                    if old_pseudo in fl:
                        new_list = [new_pseudo if f == old_pseudo else f for f in fl]
                        save_friendlist_to_db(cursor, u_id, new_list)
                connection.commit()
                user["pseudo"] = new_pseudo
                print(colorama.Fore.GREEN + "Pseudo mis à jour.")
            else:
                print(colorama.Fore.RED + "Pseudo trop court.")
        elif choice == "2":
            new_password = input(colorama.Fore.CYAN + "Nouveau mot de passe: ")
            if len(new_password) >= 6:
                password_hash = hash_text_bcrypt(new_password)
                cursor.execute("UPDATE users SET password = %s WHERE id = %s", (password_hash, user["ID"]))
                connection.commit()
                user["password"] = password_hash
                print(colorama.Fore.GREEN + "Mot de passe mis à jour.")
            else:
                print(colorama.Fore.RED + "Mot de passe trop court.")


def access_friend_list(user):
    print(colorama.Fore.MAGENTA + f"=== Liste d'amis {user['pseudo']} ===")
    if user["Friendlist"]:
        for friend in user["Friendlist"]:
            print(colorama.Fore.MAGENTA + f"- {friend}")
    else:
        print(colorama.Fore.MAGENTA + "Vous n'avez pas encore d'amis.")


def admin_panel():
    """Admin panel pour gérer utilisateurs et stats."""
    while True:
        print(colorama.Fore.YELLOW + "\n=== Panneau Admin ===")
        print(colorama.Fore.YELLOW + "1. Voir tous les utilisateurs")
        print(colorama.Fore.YELLOW + "2. Supprimer un utilisateur")
        print(colorama.Fore.YELLOW + "3. Voir statistiques de la base")
        print(colorama.Fore.YELLOW + "4. Voir les rôles des utilisateurs")
        print(colorama.Fore.YELLOW + "5. Rank up un utilisateur")
        print(colorama.Fore.YELLOW + "6. Rank down un utilisateur")
        print(colorama.Fore.YELLOW + "7. DROP ALL TABLES")
        print(colorama.Fore.YELLOW + "8. Retour au menu principal")

        choice = input(colorama.Fore.YELLOW + "Choisissez une option: ")

        with connection.cursor() as cursor:
            if choice == "1":
                # Voir tous les utilisateurs
                cursor.execute("SELECT id, pseudo_hash, Role, Created_At FROM users")
                rows = cursor.fetchall()
                print(colorama.Fore.GREEN + "\nListe des utilisateurs :")
                for uid, pseudo_hash_db, role, created_at in rows:
                    pseudo = "<pseudo inconnu>"
                    # tentative de décryptage du pseudo (bcrypt => pseudo en clair impossible, donc affichage hash)
                    pseudo = pseudo_hash_db.hex()[:10] + "..."  
                    print(f"ID:{uid} | Pseudo Hash:{pseudo} | Rôle:{role} | Créé le:{created_at}")

            elif choice == "2":
                # Supprimer un utilisateur
                user_to_del = input(colorama.Fore.CYAN + "Entrez le pseudo à supprimer: ")
                found = False
                cursor.execute("SELECT id, pseudo_hash FROM users")
                for uid, pseudo_hash_db in cursor.fetchall():
                    if verify_hash(user_to_del, pseudo_hash_db):
                        found = True
                        # supprimer friend_requests
                        cursor.execute("DELETE FROM friend_requests WHERE sender_id=%s OR receiver_id=%s", (uid, uid))
                        # supprimer messages
                        cursor.execute("DELETE FROM messages WHERE sender_id=%s OR receiver_id=%s", (uid, uid))
                        # supprimer utilisateur
                        cursor.execute("DELETE FROM users WHERE id=%s", (uid,))
                        connection.commit()
                        print(colorama.Fore.GREEN + f"Utilisateur '{user_to_del}' supprimé avec succès !")
                        break
                if not found:
                    print(colorama.Fore.RED + "Utilisateur introuvable.")

            elif choice == "3":
                # Stats de la base
                cursor.execute("SELECT COUNT(*) FROM users")
                total_users = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM messages")
                total_messages = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM friend_requests")
                total_requests = cursor.fetchone()[0]
                print(colorama.Fore.GREEN + f"\nStats : Utilisateurs={total_users}, Messages={total_messages}, Demandes d'ami={total_requests}")

            elif choice == "4":
                # Voir roles
                cursor.execute("SELECT id, pseudo_hash, Role FROM users")
                print(colorama.Fore.GREEN + "\nRôles des utilisateurs :")
                for uid, pseudo_hash_db, role in cursor.fetchall():
                    pseudo = pseudo_hash_db.hex()[:10] + "..."
                    print(f"ID:{uid} | Pseudo Hash:{pseudo} | Rôle:{role}")

            elif choice == "5":
                # Rank up
                user_rank = input(colorama.Fore.CYAN + "Pseudo à rank up: ")
                cursor.execute("SELECT id, pseudo_hash, Role FROM users")
                found = False
                for uid, pseudo_hash_db, role in cursor.fetchall():
                    if verify_hash(user_rank, pseudo_hash_db):
                        found = True
                        if role == "user":
                            new_role = "moderator"
                        elif role == "moderator":
                            new_role = "admin"
                        else:
                            new_role = role
                        cursor.execute("UPDATE users SET Role=%s WHERE id=%s", (new_role, uid))
                        connection.commit()
                        print(colorama.Fore.GREEN + f"Utilisateur '{user_rank}' passé de {role} à {new_role}")
                        break
                if not found:
                    print(colorama.Fore.RED + "Utilisateur introuvable.")

            elif choice == "6":
                # Rank down
                user_rank = input(colorama.Fore.CYAN + "Pseudo à rank down: ")
                cursor.execute("SELECT id, pseudo_hash, Role FROM users")
                found = False
                for uid, pseudo_hash_db, role in cursor.fetchall():
                    if verify_hash(user_rank, pseudo_hash_db):
                        found = True
                        if role == "admin":
                            new_role = "moderator"
                        elif role == "moderator":
                            new_role = "user"
                        else:
                            new_role = role
                        cursor.execute("UPDATE users SET Role=%s WHERE id=%s", (new_role, uid))
                        connection.commit()
                        print(colorama.Fore.GREEN + f"Utilisateur '{user_rank}' descendu de {role} à {new_role}")
                        break
                if not found:
                    print(colorama.Fore.RED + "Utilisateur introuvable.")
            elif choice == "7":
                drop_all_tables()
            elif choice == "8":
                # Retour
                break

            else:
                print(colorama.Fore.RED + "Option invalide.")

def drop_all_tables():
    confirmation = input(colorama.Fore.RED + "Tu es sûr de vouloir supprimer **toutes les tables** ? Tape 'OUI' pour confirmer: ")
    if confirmation != "OUI":
        print(colorama.Fore.YELLOW + "Suppression annulée.")
        return
    else:
        try:
            with connection.cursor() as cursor:
                # désactiver temporairement les contraintes pour éviter les erreurs de dépendances
                cursor.execute("DROP TABLE IF EXISTS messages CASCADE;")
                cursor.execute("DROP TABLE IF EXISTS friend_requests CASCADE;")
                cursor.execute("DROP TABLE IF EXISTS users CASCADE;")
                connection.commit()
            print(colorama.Fore.GREEN + "Toutes les tables ont été supprimées avec succès !")
            quit_program()
        except Exception as e:
            print(colorama.Fore.RED + f"Erreur lors de la suppression des tables: {e}")
            try:
                connection.rollback()
            except Exception:
                pass

def register_user():
    pseudo = input(colorama.Fore.CYAN + "Pseudo (min 3 caractères): ")
    if len(pseudo) < 3:
        print(colorama.Fore.RED + "Pseudo trop court.")
        return

    with connection.cursor() as cursor:
        cursor.execute("SELECT pseudo_hash FROM users")
        all_hashed_pseudos = cursor.fetchall()

        for (hashed_pseudo,) in all_hashed_pseudos:
            if verify_hash(pseudo, hashed_pseudo):
                print(colorama.Fore.RED + "Ce pseudo est déjà utilisé.")
                return

        password = input(colorama.Fore.CYAN + "Mot de passe (min 6 caractères): ")
        if len(password) < 6:
            print(colorama.Fore.RED + "Mot de passe trop court.")
            return

        pseudo_hash = hash_text_bcrypt(pseudo)
        password_hash = hash_text_bcrypt(password)
        Created_At = time.strftime("%Y-%m-%d %H:%M:%S")
        # friendlist initial vide
        cursor.execute(
            "INSERT INTO users (pseudo_hash, password, friendlist, Created_At) VALUES (%s, %s, %s, %s)",
            (pseudo_hash, password_hash, encrypt_json([]), Created_At),
        )
        connection.commit()
        print(colorama.Fore.GREEN + f"Utilisateur enregistré: {pseudo}")


def login_user():
    pseudo = input(colorama.Fore.CYAN + "Pseudo: ")
    password = input(colorama.Fore.CYAN + "Mot de passe: ")

    with connection.cursor() as cursor:
        row = get_user_row_by_pseudo(cursor, pseudo)
        if row:
            uid, stored_pseudo_hash, stored_password_hash, role, friendlist_enc, created_at = row
            if verify_hash(password, stored_password_hash):
                friendlist = decrypt_json(friendlist_enc) if friendlist_enc else []
                print(colorama.Fore.GREEN + f"Connexion réussie: {pseudo}")
                connect_user(pseudo, stored_password_hash, uid, friendlist, role, created_at)
                return
            else:
                print(colorama.Fore.RED + "Mot de passe incorrect.")
                return
        print(colorama.Fore.RED + "Utilisateur non trouvé.")


# ------------------ MENU ------------------
def menu():
    while True:
        print(colorama.Fore.CYAN + "=== Menu Principal ===")
        print(colorama.Fore.CYAN + "1. S'inscrire")
        print(colorama.Fore.CYAN + "2. Se connecter")
        print(colorama.Fore.CYAN + "3. Quitter")
        choice = input(colorama.Fore.CYAN + "Choisissez une option: ")
        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            quit_program()
        else:
            print(colorama.Fore.RED + "Option invalide.")


def quit_program():
    global stop_threads
    stop_threads = True
    close_connection(connection)
    print(colorama.Fore.MAGENTA + "Fermeture du programme...")
    exit(0)


# ------------------ DATABASE INITIALIZATION ------------------
connection = connect_to_db(host, database, db_user, db_password, port)

# Création des tables (ajouté sender_name pour faciliter affichage)
try:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                pseudo_hash BYTEA NOT NULL UNIQUE,
                password BYTEA NOT NULL,
                Role TEXT DEFAULT 'user',
                friendlist BYTEA,
                Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )
        connection.commit()
except SQL.Error as e:
    print(colorama.Fore.RED + f"Erreur table users: {e}")
    try:
        connection.rollback()
    except Exception:
        pass

try:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS friend_requests (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER REFERENCES users(id),
                receiver_id INTEGER REFERENCES users(id),
                sender_name TEXT,
                status BYTEA,
                status_hash BYTEA,
                Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """
        )
        connection.commit()
except SQL.Error as e:
    print(colorama.Fore.RED + f"Erreur table friend_requests: {e}")
    try:
        connection.rollback()
    except Exception:
        pass

try:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER REFERENCES users(id),
                receiver_id INTEGER REFERENCES users(id),
                content BYTEA NOT NULL,
                Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )
        connection.commit()
except SQL.Error as e:
    print(colorama.Fore.RED + f"Erreur table messages: {e}")
    try:
        connection.rollback()
    except Exception:
        pass

# Si aucun utilisateur admin par défaut (pratique pour dev), on peut insérer un admin
try:
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        if count == 0:
            password_hash = hash_text_bcrypt("ilanleboss")
            admin_pseudo = "yolezz"
            cursor.execute(
                "INSERT INTO users (pseudo_hash, password, friendlist, Role) VALUES (%s, %s, %s, %s)",
                (hash_text_bcrypt(admin_pseudo), password_hash, encrypt_json([]), "admin"),
            )
            connection.commit()
except SQL.Error as e:
    print(colorama.Fore.RED + f"Erreur insertion admin: {e}")
    try:
        connection.rollback()
    except Exception:
        pass


if __name__ == "__main__":
    menu()
    quit_program()
import os
import re
import sys
import requests
import subprocess
import psycopg2 as SQL
import threading
import time
import bcrypt
import json
from sshtunnel import SSHTunnelForwarder
from cryptography.fernet import Fernet
from colorama import init, Fore, Style

init()
print(Style.RESET_ALL, end="")

# colorama config
r = Fore.RED
g = Fore.GREEN
y = Fore.YELLOW
b = Fore.BLUE
c = Fore.CYAN
m = Fore.MAGENTA
reset = Style.RESET_ALL

# -------Configuration-------
version_actuelle = "V1.2"
dst = os.path.dirname(os.path.abspath(__file__))
GITHUB_API_URL = "https://api.github.com/repos/yo-le-zz/chat_online/contents/version"
connection = None
tunnel = None
stop_threads = False
ssh_host = "192.168.1.99"
ssh_user = "ilan"
ssh_password = "2012-2025!"

db_user = "ilan"
db_password = "FhARs9RZsw4/SyYX/xk04rrf"
db_name = "chat_app_db"
db_port = 5432
# ---------------------------

# ------------------- CRYPTO / HASH -------------------
key = "xC8xYQs-xinPKJmtK_GuzsZZ-6F5IacXtabOOsGoSaw=".encode()
fernet = Fernet(key)


def encrypt_text(text: str) -> bytes:
    if text is None:
        return None
    try:
        return fernet.encrypt(text.encode("utf-8"))
    except Exception as e:
        print(f"{r}Erreur encrypt_text: {e}")
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
        print(f"{r}Erreur decrypt_text: {e}")
        return None


def encrypt_json(obj) -> bytes:
    try:
        return encrypt_text(json.dumps(obj, ensure_ascii=False))
    except Exception as e:
        print(f"{r}Erreur encrypt_json: {e}")
        return None


def decrypt_json(token):
    if token is None:
        return []
    try:
        txt = decrypt_text(token)
        return json.loads(txt) if txt else []
    except Exception as e:
        print(f"{r}Erreur decrypt_json: {e}")
        return []


def hash_text_bcrypt(text: str) -> bytes:
    """Hash avec bcrypt (pour pseudo, mot de passe, status, message-hash if needed)"""
    if text is None:
        return None
    try:
        return bcrypt.hashpw(text.encode("utf-8"), bcrypt.gensalt())
    except Exception as e:
        print(f"{r}Erreur hash_text_bcrypt: {e}")
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
        print(f"{r}Erreur verify_hash: {e}")
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
        print(f"{g}Connexion à la base de données réussie.")
        return connection
    except SQL.Error as e:
        print(f"{r}Erreur de connexion: {e}")
        return None

def open_ssh_tunnel():
    """Ouvre un tunnel SSH et renvoie l'objet tunnel + la connexion PostgreSQL."""
    try:
        tunnel = SSHTunnelForwarder(
            (ssh_host, 22),
            ssh_username=ssh_user,
            ssh_password=ssh_password,
            remote_bind_address=('127.0.0.1', 5432),
            local_bind_address=('127.0.0.1', 6543)
        )
        tunnel.start()
        print(f"{y}✅ Tunnel SSH ouvert sur le port local {tunnel.local_bind_port}")

        connection = connect_to_db(
            host='127.0.0.1',
            database=db_name,
            user=db_user,
            password=db_password,
            port=tunnel.local_bind_port
        )
        if connection is None:
            print(f"{r}❌ Aucune connexion active à la base. Vérifie le tunnel SSH et les identifiants.")
            exit(1)

        if connection:
            print(f"{g}✅ Connexion PostgreSQL établie via SSH.")
        else:
            print(f"{r}❌ Échec de la connexion à PostgreSQL via SSH.")

        return tunnel, connection
    except Exception as e:
        print(f"{r}Erreur lors de l'ouverture du tunnel SSH: {e}")
        return None, None


def close_connection(connection):
    if connection:
        connection.close()
        print(f"{g}Connexion fermée.")


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
        print(f"{r}Erreur vérification table: {e}")
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
        print(f"{r}Erreur get_user_row_by_pseudo: {e}")
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
                    print(f"{c}\n[{ts}] {plain}")

                if new_messages:
                    last_checked = new_messages[-1][2]
        except Exception as e:
            print(f"{r}Erreur dans receive_messages: {e}")
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
                        print(f"{c}Nouvelle demande d'ami de: {display_name}")
                        accept = input("{c}Accepter la demande ? (o/n): ")
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
                        print((f"{g}Demande acceptée." if new_status == "accepted" else "Demande rejetée."))
        except Exception as e:
            print(f"{r}Erreur dans check_friend_requests: {e}")
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
                                print(f"{y}L'ami '{friend}' vous a supprimé de sa liste.")
                            break
                    if not friend_found:
                        print(f"{y}L'ami '{friend}' a supprimé son compte.")
                # Mettre à jour uniquement si nécessaire
                if set(updated_friendlist) != set(Friendlist):
                    Friendlist[:] = updated_friendlist
                    save_friendlist_to_db(cursor, ID, Friendlist)
                    cursor.connection.commit()
        except Exception as e:
            print(f"{r}Erreur verifier_si_un_ami_a_supprimer_son_compte: {e}")
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
                    print(f"{g}\nVotre demande d'ami a été acceptée par {sender_name} !\n")
                    # mettre à jour la friendlist locale
                    with connection.cursor() as cur2:
                        cur2.execute("SELECT friendlist FROM users WHERE id = %s", (user["ID"],))
                        row = cur2.fetchone()
                        user["Friendlist"] = decrypt_json(row[0]) if row and row[0] else []
                    handled = True

                # vérifier si rejeté
                elif status_hash and verify_hash("rejected", status_hash):
                    print(f"{r}\nVotre demande d'ami a été rejetée par {sender_name}.\n")
                    handled = True

        except Exception as e:
            print(f"{r}Erreur dans friend_request_listener: {e}")
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
    print(f"{g}Utilisateur connecté: {pseudo}, avec le rôle: {Role}")

    threading.Thread(target=verifier_si_un_ami_a_supprimer_son_compte, args=(Friendlist, user, ID), daemon=True).start()
    threading.Thread(target=check_friend_requests, args=(ID,), daemon=True).start()
    # check_friend_status referenced elsewhere; ensure it exists if used
    # threading.Thread(target=check_friend_status, args=(user,), daemon=True).start()

    while True:
        print(f"{c}=== Comptes de l'{Role} : {pseudo} ===")
        print(f"{c}1. Voir les informations du compte")
        print(f"{c}2. Modifier les informations du compte")
        print(f"{c}3. Ajouter un ami")
        print(f"{c}4. Supprimer un ami")
        print(f"{c}5. Accéder à la liste d'amis")
        print(f"{c}6. Accéder au chat")
        if Role == "admin":
            print(f"{y}7. Accéder au panneau d'administration")
            print(f"{c}8. Se déconnecter")
            print(f"{c}9. Quitter")
        else:
            print(f"{c}7. Se déconnecter")
            print(f"{c}8. Supprimer le compte")
            print(f"{c}9. Quitter")
        choice = input(f"{c}Choisissez une option: ")

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
            print(f"{r}Option invalide.")
    menu()


def chat(user):
    if not user["Friendlist"]:
        print(f"{m}Tu n’as encore aucun ami.")
        return

    print("=== Chat avec tes amis ===")
    for i, ami in enumerate(user["Friendlist"], start=1):
        print(f"{c}{i}. {ami}")

    choix = input(f"{c}Tape le numéro de l'ami avec qui tu veux discuter: ")
    if not choix.isdigit():
        print(f"{r}Erreur : tu dois entrer un numéro.")
        return

    index = int(choix) - 1
    if index < 0 or index >= len(user["Friendlist"]):
        print(f"{r}Erreur : numéro invalide.")
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
            print(f"{r}Utilisateur introuvable.")
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

        print(f"{m}=== Conversation avec {ami_choisi} ===")
        for sender_id, content, date in messages:
            sender_name = user["pseudo"] if sender_id == user["ID"] else ami_choisi
            try:
                plain = decrypt_text(content)
            except Exception:
                plain = "<message illisible>"
            print(f"{c}[{date}] {sender_name}: {plain}")

    stop_chat_event = threading.Event()
    thread_reception = threading.Thread(target=receive_messages, args=(user["ID"], ami_id, stop_chat_event), daemon=True)
    thread_reception.start()

    while True:
        message = input(f"{c}Entrer un message (ou 'exit') : ").strip()
        if message.lower() == "exit":
            print(f"{y}Fin du chat.")
            stop_chat_event.set()
            thread_reception.join()
            break

        if not message:
            print(f"{r}Erreur : le message ne peut pas être vide.")
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

        print(f"{m}[{user['pseudo']}] {message}")


def delete_friend(user):
    print(f"{c}=== Supprimer un ami ===")
    friend_pseudo = input(f"{c}Entrez le pseudo de l'ami à supprimer: ")

    if friend_pseudo not in user["Friendlist"]:
        print(f"{r}Aucun ami trouvé avec le pseudo: {friend_pseudo}.")
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

    print(f"{g}Ami '{friend_pseudo}' supprimé avec succès, et messages supprimés.")



def add_friend(user):
    print(f"{c}=== Ajouter un ami ===")
    friend_pseudo = input(f"{c}Entrez le pseudo de l'ami à ajouter: ")
    if friend_pseudo == user["pseudo"]:
        print(f"{r}Vous ne pouvez pas vous ajouter vous-même!")
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
            print(f"{g}Demande d'ami envoyée à {friend_pseudo}.")
        else:
            print(f"{r}Aucun utilisateur trouvé avec le pseudo: {friend_pseudo}.")


def del_compte(user):
    print(f"{r}=== Suppression du compte ===")
    confirmation = input(f"{r}Tapez 'OUI' pour confirmer la suppression: ")
    if confirmation != "OUI":
        print(f"{y}Suppression annulée.")
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
    print(f"{g}Compte supprimé avec succès.")


def view_account_info(user):
    print(f"{m}=== Infos compte {user['pseudo']} ===")
    print(f"{m}ID: {user['ID']}")
    print(f"{m}Pseudo: {user['pseudo']}")
    # password is stored as bcrypt bytes
    hashed_password_bytes = user["password"] if isinstance(user["password"], (bytes, bytearray)) else bytes(user["password"])
    print(f"{m}Mot de passe (hashé): {hashed_password_bytes.hex()}")
    print(f"{m}Role: {user['Role']}")
    print(f"{m}Date de création: {user['Created_At']}")


def modify_account_info(user):
    print(f"{c}=== Modifier le compte ===")
    print(f"{c}1. Modifier le pseudo")
    print(f"{c}2. Modifier le mot de passe")
    choice = input(f"{c}Choisissez: ")
    with connection.cursor() as cursor:
        if choice == "1":
            new_pseudo = input(f"{c}Nouveau pseudo: ")
            if len(new_pseudo) >= 3:
                # vérifier unicité en parcourant les pseudo_hash
                cursor.execute("SELECT pseudo_hash FROM users")
                existing = cursor.fetchall()
                for (h,) in existing:
                    if verify_hash(new_pseudo, h):
                        print(f"{r}Ce pseudo est déjà utilisé.")
                        return
                old_pseudo = user["pseudo"]
                # mettre à jour pseudo_hash (bcrypt) et friendlists
                new_pseudo_hash = hash_text_bcrypt(new_pseudo)
                new_pseudo_enc = encrypt_text(new_pseudo)
                cursor.execute("UPDATE users SET pseudo_hash = %s WHERE id = %s", (new_pseudo_hash, user["ID"]))
                cursor.execute("UPDATE users SET pseudo_enc = %s WHERE id = %s", (new_pseudo_enc, user["ID"]))
                cursor.execute("SELECT id, friendlist FROM users")
                all_users = cursor.fetchall()
                for u_id, fl_enc in all_users:
                    fl = decrypt_json(fl_enc) or []
                    if old_pseudo in fl:
                        new_list = [new_pseudo if f == old_pseudo else f for f in fl]
                        save_friendlist_to_db(cursor, u_id, new_list)
                connection.commit()
                user["pseudo"] = new_pseudo
                print(f"{g}Pseudo mis à jour.")
            else:
                print(f"{r}Pseudo trop court.")
        elif choice == "2":
            new_password = input(f"{c}Nouveau mot de passe: ")
            if len(new_password) >= 6:
                password_hash = hash_text_bcrypt(new_password)
                cursor.execute("UPDATE users SET password = %s WHERE id = %s", (password_hash, user["ID"]))
                connection.commit()
                user["password"] = password_hash
                print(f"{g}Mot de passe mis à jour.")
            else:
                print(f"{r}Mot de passe trop court.")


def access_friend_list(user):
    print(f"{m}=== Liste d'amis {user['pseudo']} ===")
    if user["Friendlist"]:
        for friend in user["Friendlist"]:
            print(f"{m}- {friend}")
    else:
        print(f"{m}Vous n'avez pas encore d'amis.")


def admin_panel():
    """Admin panel pour gérer utilisateurs et stats."""
    while True:
        print(f"{y}\n=== Panneau Admin ===")
        print(f"{y}1. Voir tous les utilisateurs")
        print(f"{y}2. Supprimer un utilisateur")
        print(f"{y}3. Voir statistiques de la base")
        print(f"{y}4. Voir les rôles des utilisateurs")
        print(f"{y}5. Rank up un utilisateur")
        print(f"{y}6. Rank down un utilisateur")
        print(f"{y}7. DROP ALL TABLES")
        print(f"{y}8. Retour au menu principal")

        choice = input(f"{y}Choisissez une option: ")

        with connection.cursor() as cursor:
            if choice == "1":
                # Voir tous les utilisateurs
                cursor.execute("SELECT id, pseudo_enc, role, created_at FROM users")
                rows = cursor.fetchall()
                print(f"{g}\nListe des utilisateurs :")
                for user_id, pseudo_enc, role, created_at in rows:
                    try:
                        pseudo = decrypt_text(pseudo_enc)
                    except Exception:
                        pseudo = "<erreur de déchiffrement>"
                    print(f"ID:{user_id} | Pseudo:{pseudo} | Rôle:{role} | Créé le:{created_at}")

            elif choice == "2":
                # Supprimer un utilisateur
                user_to_del = input(f"{c}Entrez le pseudo à supprimer: ")
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
                        print(f"{g}Utilisateur '{user_to_del}' supprimé avec succès !")
                        break
                if not found:
                    print(f"{r}Utilisateur introuvable.")

            elif choice == "3":
                # Stats de la base
                cursor.execute("SELECT COUNT(*) FROM users")
                total_users = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM messages")
                total_messages = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM friend_requests")
                total_requests = cursor.fetchone()[0]
                print(f"{g}\nStats : Utilisateurs={total_users}, Messages={total_messages}, Demandes d'ami={total_requests}")

            elif choice == "4":
                # Voir roles
                cursor.execute("SELECT id, pseudo_hash, Role FROM users")
                print(f"{g}\nRôles des utilisateurs :")
                for uid, pseudo_hash_db, role in cursor.fetchall():
                    pseudo = pseudo_hash_db.hex()[:10] + "..."
                    print(f"ID:{uid} | Pseudo Hash:{pseudo} | Rôle:{role}")

            elif choice == "5":
                # Rank up
                user_rank = input(f"{c}Pseudo à rank up: ")
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
                        print(f"{g}Utilisateur '{user_rank}' passé de {role} à {new_role}")
                        break
                if not found:
                    print(f"{r}Utilisateur introuvable.")

            elif choice == "6":
                # Rank down
                user_rank = input(f"{c}Pseudo à rank down: ")
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
                        print(f"{g}Utilisateur '{user_rank}' descendu de {role} à {new_role}")
                        break
                if not found:
                    print(f"{r}Utilisateur introuvable.")
            elif choice == "7":
                drop_all_tables()
            elif choice == "8":
                # Retour
                break

            else:
                print(f"{r}Option invalide.")

def drop_all_tables():
    confirmation = input(f"{r}Tu es sûr de vouloir supprimer **toutes les tables** ? Tape 'OUI' pour confirmer: ")
    if confirmation != "OUI":
        print(f"{y}Suppression annulée.")
        return
    else:
        try:
            with connection.cursor() as cursor:
                # désactiver temporairement les contraintes pour éviter les erreurs de dépendances
                cursor.execute("DROP TABLE IF EXISTS messages CASCADE;")
                cursor.execute("DROP TABLE IF EXISTS friend_requests CASCADE;")
                cursor.execute("DROP TABLE IF EXISTS users CASCADE;")
                connection.commit()
            print(f"{g}Toutes les tables ont été supprimées avec succès !")
            quit_program()
        except Exception as e:
            print(f"{r}Erreur lors de la suppression des tables: {e}")
            try:
                connection.rollback()
            except Exception:
                pass

def register_user():
    pseudo = input(f"{c}Pseudo (min 3 caractères): ")
    if len(pseudo) < 3:
        print(f"{r}Pseudo trop court.")
        return

    with connection.cursor() as cursor:
        cursor.execute("SELECT pseudo_hash FROM users")
        all_hashed_pseudos = cursor.fetchall()

        for (hashed_pseudo,) in all_hashed_pseudos:
            if verify_hash(pseudo, hashed_pseudo):
                print(f"{r}Ce pseudo est déjà utilisé.")
                return

        password = input(f"{c}Mot de passe (min 6 caractères): ")
        if len(password) < 6:
            print(f"{r}Mot de passe trop court.")
            return

        pseudo_hash = hash_text_bcrypt(pseudo)
        pseudo_enc = encrypt_text(pseudo)
        password_hash = hash_text_bcrypt(password)
        Created_At = time.strftime("%Y-%m-%d %H:%M:%S")
        # friendlist initial vide
        cursor.execute(
            "INSERT INTO users (pseudo_hash, pseudo_enc, password, friendlist, Created_At) VALUES (%s, %s, %s, %s, %s)",
            (pseudo_hash, pseudo_enc, password_hash, encrypt_json([]), Created_At)
        )
        connection.commit()
        print(f"{g}Utilisateur enregistré: {pseudo}")


def login_user():
    pseudo = input(f"{c}Pseudo: ")
    password = input(f"{c}Mot de passe: ")

    with connection.cursor() as cursor:
        row = get_user_row_by_pseudo(cursor, pseudo)
        if row:
            uid, stored_pseudo_hash, stored_password_hash, role, friendlist_enc, created_at = row
            if verify_hash(password, stored_password_hash):
                friendlist = decrypt_json(friendlist_enc) if friendlist_enc else []
                print(f"{g}Connexion réussie: {pseudo}")
                connect_user(pseudo, stored_password_hash, uid, friendlist, role, created_at)
                return
            else:
                print(f"{r}Mot de passe incorrect.")
                return
        print(f"{r}Utilisateur non trouvé.")


# ------------------ MENU ------------------
def menu():
    while True:
        print(f"{c}=== Menu Principal ===")
        print(f"{c}Version actuelle : {version_actuelle}")
        print(f"{c}1. S'inscrire")
        print(f"{c}2. Se connecter")
        print(f"{c}3. Vérifier si une nouvelle version existe et la télécharger")
        print(f"{c}4. Installer une version spécifique (ancienne ou autre)")
        print(f"{c}5. Quitter")

        choix = input("Votre choix : ").strip()

        if choix == "1":
            register_user()
        elif choix == "2":
            login_user()
        elif choix == "3":
            check_version(version_actuelle, GITHUB_API_URL, script_mise_a_jour)
        elif choix == "4":
            versions = get_all_versions("yo-le-zz", "chat_online")
            if not versions:
                print(f"{r}❌ Aucune version disponible.")
                continue
            print(f"{c}Versions disponibles :", ", ".join(versions))
            v = input(f"{c}Entrez la version à installer : ").strip()
            if v not in versions:
                print(f"{r}❌ Version inconnue.")
                continue
            print(f"{m}Installation de {v}...")
            installer_old_version(v)
            
        elif choix == "5":
            quit_program()
        else:
            print(f"{r}Option invalide.")


def quit_program():
    global stop_threads
    stop_threads = True
    close_connection(connection)
    print(f"{m}Fermeture du programme...")
    exit(0)


# ------------------ DATABASE INITIALIZATION ------------------

if __name__ == "__main__":
    # Établir la connexion en premier
    tunnel, connection = open_ssh_tunnel()
    if not connection:
        print(f"{r}❌ Impossible d'établir la connexion SSH/DB. Fermeture du programme.")
        exit(1)

    # Création des tables une fois la connexion établie
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    pseudo_hash BYTEA NOT NULL UNIQUE,
                    pseudo_enc BYTEA NOT NULL UNIQUE,
                    password BYTEA NOT NULL,
                    Role TEXT DEFAULT 'user',
                    friendlist BYTEA,
                    Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            connection.commit()
    except SQL.Error as e:
        print(f"{r}Erreur table users: {e}")
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
        print(f"{r}Erreur table friend_requests: {e}")
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
        print(f"{r}Erreur table messages: {e}")
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
                
                admin_pseudo = "yolezz"
                pseudo_enc = fernet.encrypt(admin_pseudo.encode())

                cursor.execute(
                    "INSERT INTO users (pseudo_hash, password, friendlist, Role, pseudo_enc) VALUES (%s, %s, %s, %s, %s)",
                    (hash_text_bcrypt(admin_pseudo), password_hash, encrypt_json([]), "admin", pseudo_enc),
                )
                connection.commit()
    except SQL.Error as e:
        print(f"{r}Erreur insertion admin: {e}")
        try:
            connection.rollback()
        except Exception:
            pass

# version fonction --------------

def extraire_version(v: str):
    """Extrait une version sous forme de tuple d'entiers (ex: V1.3 -> (1, 3))."""
    m = re.match(r"V(\d+(?:\.\d+)*)$", v)
    if not m:
        return ()
    return tuple(map(int, m.group(1).split(".")))

def check_version(version_locale: str, api_url: str, script_mise_a_jour):
    """Compare la version locale avec les versions disponibles sur GitHub."""
    version_num = extraire_version(version_locale)

    # Appel à l'API GitHub
    r = requests.get(api_url)
    if r.status_code != 200:
        print(f"Erreur HTTP {r.status_code} : impossible d’accéder au dépôt GitHub")
        return

    contenus = r.json()
    versions = []

    for item in contenus:
        if item["type"] == "dir" and re.match(r"V\d+(\.\d+)*$", item["name"]):
            versions.append(extraire_version(item["name"]))

    if not versions:
        print("Aucune version trouvée sur GitHub.")
        return

    global derniere_version
    derniere_version = max(versions)
    if derniere_version > version_num:
        new_version = f"V{'.'.join(map(str, derniere_version))}"
        print(f"Nouvelle version disponible : {new_version}")
        print("Passage à la nouvelle version (ne désactivez pas votre ordinateur).")

        # injection de la bonne version dans le script de mise à jour
        script_final = script_mise_a_jour.replace('new_version = ""', f'new_version = "{new_version}"')

        with open(os.path.join(dst, "transistor_version.py"), "w", encoding="utf-8") as f:
            f.write(script_final)

        subprocess.Popen([sys.executable, os.path.join(dst, "transistor_version.py")])
        sys.exit(0)


# --- Script de mise à jour (sera injecté dans transistor_version.py) ---

script_mise_a_jour = r"""
import requests
import os
import shutil
import sys
import time
import psutil
from colorama import init, Fore, Style

init()

# colorama config
r = Fore.RED
g = Fore.GREEN
b = Fore.BLUE
c = Fore.CYAN
m = Fore.MAGENTA
reset = Style.RESET_ALL

version = "V1.3"
new_version = ""  # sera remplacé par la vraie version avant exécution

dst = os.path.dirname(os.path.abspath(__file__))
main_path = os.path.join(dst, "main.py")

def get_src_path():
    return os.path.join(dst, new_version, "main.py")

def download_github_folder(owner, repo, path, output_dir="."):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    response = requests.get(url)
    response.raise_for_status()
    items = response.json()

    if not isinstance(items, list):
        print(f"{r}❌ Le chemin indiqué n'est pas un dossier valide sur GitHub.")
        return

    full_output_dir = os.path.join(dst, output_dir)
    os.makedirs(full_output_dir, exist_ok=True)

    for item in items:
        if item["type"] == "file":
            print(f"Téléchargement de {item['name']}...")
            file_data = requests.get(item["download_url"])
            file_data.raise_for_status()

            file_path = os.path.join(full_output_dir, item["name"])
            print(f"{m}📂 Enregistrement dans : {file_path}")

            with open(file_path, "wb") as f:
                f.write(file_data.content)

        elif item["type"] == "dir":
            sub_dir = os.path.join(full_output_dir, item["name"])
            download_github_folder(owner, repo, item["path"], sub_dir)


            
def stop_old_script(script_name="main.py"):
    current_pid = os.getpid()
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if (
                proc.info["pid"] != current_pid
                and "python" in proc.info["name"].lower()
                and any(script_name in str(arg) for arg in proc.info["cmdline"])
            ):
                print(f"{r}🛑 Arrêt du processus : {proc.info['pid']}")
                proc.terminate()
                proc.wait(timeout=5)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

def delete(path):
    if os.path.exists(path):
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)

print(f"{m}🚀 Téléchargement de la nouvelle version...")
download_github_folder(
    owner="yo-le-zz",
    repo="chat_online",
    path=f"version/{new_version}",
    output_dir=f"{new_version}"
)

print(f"{r}🛑 Tentative d'arrêt de l'ancien script...")
stop_old_script("main.py")
time.sleep(1)

if os.path.exists(main_path):
    print("🧹 Suppression de l'ancien main.py...")
    delete(main_path)

src = get_src_path()
print(f"{m}📦 Installation de la nouvelle version depuis {src}...")

if not os.path.exists(src):
    print(f"{r}❌ Fichier introuvable : {src}")
    sys.exit(1)

shutil.move(src, main_path)

print(f"{reset}🗑️ Nettoyage du dossier de version...")
delete(os.path.join(dst, new_version))
delete(os.path.join(dst, "transistor_version.py"))

print(f"{g}✅ Mise à jour terminée. Relance du script...")
os.execv(sys.executable, [sys.executable, main_path])
"""



def get_all_versions(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/version"
    r = requests.get(url)
    if r.status_code != 200:
        print(f"Erreur HTTP {r.status_code} lors de la récupération des versions.")
        return []
    items = r.json()
    versions = [item["name"] for item in items if item["type"] == "dir" and item["name"].startswith("V")]
    return sorted(versions, key=lambda v: list(map(int, v[1:].split('.'))))

def installer_old_version(v):
    print("Passage à l'ancienne version (ne désactivez pas votre ordinateur).")

    # injection de la bonne version dans le script de mise à jour
    script_final = script_mise_a_jour.replace('new_version = ""', f'new_version = "{v}"')

    with open(os.path.join(dst, "transistor_version.py"), "w", encoding="utf-8") as f:
        f.write(script_final)

    subprocess.Popen([sys.executable, os.path.join(dst, "transistor_version.py")])

# === MENU ===

menu()
quit_program()
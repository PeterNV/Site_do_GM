from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth import get_user_model
import pymongo

class MongoDBBackend:
    def authenticate(self, request, email=None, password=None):
        if not email or not password:
            return None

        try:
            # Conexão com o MongoDB
            client = pymongo.MongoClient("mongodb+srv://GM:GeracaoM126@cluster0.peur7xa.mongodb.net/")
            db = client["Dados"]
            usuarios = db["Usuarios"]

            # Busca o usuário pelo e-mail
            usuario_data = usuarios.find_one({"Email": email})
            if not usuario_data:
                print("Usuário não encontrado.")
                return None

            # Verifica se a senha está hasheada ou em texto puro
            senha_mongo = usuario_data.get("Senha")
            if not senha_mongo:
                print("Senha não encontrada.")
                return None

            if senha_mongo.startswith("pbkdf2_sha256$"):
                if not check_password(password, senha_mongo):
                    print("Senha incorreta.")
                    return None
            else:
                if password != senha_mongo:
                    print("Senha incorreta (em texto puro).")
                    return None
                # Atualiza a senha para o formato Django
                senha_mongo = make_password(password)
                usuarios.update_one(
                    {"_id": usuario_data["_id"]},
                    {"$set": {"Senha": senha_mongo}}
                )
                print("Senha convertida para hash Django.")

            # Cria ou atualiza usuário no Django
            return self.get_or_create_django_user(usuario_data, senha_mongo)

        except Exception as e:
            print(f"Erro na autenticação: {e}")
            return None

    def get_or_create_django_user(self, mongo_data, senha_hash):
        User = get_user_model()
        email = mongo_data["Email"]
        username = email

        # Gera um ID numérico baseado no ObjectId do MongoDB
        object_id = mongo_data["_id"]
        numeric_id = int(str(object_id)[:8], 16)

        user, _ = User.objects.update_or_create(
            email=email,
            defaults={
                'id': numeric_id,
                'username': username,
                'password': senha_hash,
            }
        )
        return user

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

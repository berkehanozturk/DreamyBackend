# This is a sample Python script.
# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.
from flask import Flask, jsonify, request
from flask import make_response
import jwt
import datetime
from functools import wraps
import mysql.connector
from flask import g
import requests
import json
import base64
import google.auth.transport.requests
from google.oauth2 import service_account
import firebase_admin
from firebase_admin import credentials
import bcrypt
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gizlianahtar'
app.config["Service"] = "/Users/berkehanozturk/PycharmProjects/DreamyBE/service-account.json"
SCOPES = ['https://www.googleapis.com/auth/firebase.messaging']
mydb = mysql.connector.connect(
    host="127.0.0.1",
    user="root",
    password="Can172199400",
    database="CoreDb"
)

mycursor = mydb.cursor()


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'mesaj': 'Token eksik!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'mesaj': 'Geçersiz token!'}), 403
        return f(*args, **kwargs)

    return decorated


@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    email = auth.get('email')
    password = auth.get('password')

    if not email or not password:
        return jsonify({'errorMessage': 'Please enter username and password!'}), 401

    cursor = mydb.cursor()

    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (email,))
    user = cursor.fetchone()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
        return jsonify({'errorMessage': 'Incorrect email or password!'}), 401

    user_id = user[0]  # Extract the user ID
    token = jwt.encode({'username': user[1], 'exp': datetime.datetime.max},
                       app.config['SECRET_KEY'])
    response = make_response(jsonify({'token': token, 'userId': user_id}))
    return response


@app.route('/gizli')
@jwt_required
def gizli():
    return jsonify({'mesaj': 'Bu gizli bilgi sadece oturum açmış kullanıcılar için!'})


@app.route('/users')
@jwt_required
def get_all_users():
    # Connect to the database
    cursor = mydb.cursor()

    # Execute a parameterized query to retrieve all user data
    query = "SELECT * FROM users"
    cursor.execute(query)
    user_data = cursor.fetchall()

    # Close the database connection
    mydb.close()

    # If user data is found, return it as a JSON response
    if user_data:
        users_list = []
        for user in user_data:
            user_dict = {'id': user[0], 'email': user[1], 'password': user[2], 'fullName': user[3],
                         'coinCount': user[4]}
            users_list.append(user_dict)
        return jsonify(users_list)
    # Otherwise, return a 404 error
    else:
        return 'No users found', 404


@app.route('/getUserInformations', methods=['POST'])
@jwt_required
def getUserInformations():
    # Connect to the database
    cursor = mydb.cursor()
    # Close the database connection
    userRequest = request.get_json()
    user_id = userRequest.get("userId")
    query = "SELECT * FROM user_details WHERE user_id = %s"
    cursor.execute(query, (user_id,))
    user_data = cursor.fetchone()

    # Close the database connection
    cursor.close()
    if user_data:
        user_dict = {
            'userId': user_data[0],
            'job': user_data[1],
            'relationship': user_data[2],
            'gender': user_data[3],
            'coinCount': user_data[5]
        }
        return jsonify(user_dict)
        # Otherwise, return a 404 error
    else:
        return jsonify({'errorMessage': 'User not found'}), 404


def get_db():
    if 'mydb' not in g:
        g.db = mysql.connector.connect(
            host="127.0.0.1",
            user="root",
            password="Can172199400",
            database="CoreDb"
        )
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('mydb', None)
    if db is not None:
        db.close()


@app.route('/getDreams', methods=['Post'])
@jwt_required
def getDreams():
    # Get the user ID from the request parameters
    user_id = request.get_json().get("userId")
    if not user_id:
        return jsonify({'errorMessage': 'userId parameter is missing'}), 400

    # Connect to the database
    mydb = get_db()

    cursor = mydb.cursor()

    # Query to retrieve dream information, status, and date for the specified user
    query = "SELECT dreamInformation, dreamStatus, dreamDate ,dreamResult FROM UserDreams WHERE userId = %s"

    cursor.execute(query, (user_id,))
    dream_data = cursor.fetchall()

    coin_count_query = "SELECT coin_count FROM user_details WHERE user_id = %s"
    cursor.execute(coin_count_query, (user_id,))
    coin_count_data = cursor.fetchone()
    # Close the database connection
    cursor.close()
    coin_count = coin_count_data[0]
    if dream_data:
        dreams_list = []
        for row in dream_data:
            dream_dict = {
                'dreamInformation': row[0],
                'dreamStatus': row[1],
                'dreamDate': row[2],
                'dreamResult': row[3]
            }
            dreams_list.append(dream_dict)

        response = jsonify({'dreams': dreams_list, 'coinCount': coin_count})

    else:
        response = jsonify({'dreams': [], 'coinCount': coin_count})
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    return response


@app.route('/signup', methods=['POST'])
def signup():
    # Get user input from request body
    user_input = request.get_json()
    email = user_input.get('email')
    password = user_input.get('password')
    full_name = user_input.get('fullName')

    # Check if all required fields are present
    if not email or not password or not full_name:
        return jsonify({'errorMessage': 'Please fill the all forms'}), 400

    # Connect to MySQL database
    cursor = mydb.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Check if username already exists
    query = "SELECT * FROM users WHERE email=%s"
    cursor.execute(query, (email,))
    result = cursor.fetchone()
    if result:
        return jsonify({'errorMessage': 'User Already Registered'}), 409

    # Insert new user into database

    insert_query = "INSERT INTO users (email, password, fullName, created_at) VALUES (%s, %s, %s, %s)"
    now = datetime.datetime.utcnow()
    cursor.execute(insert_query, (email, hashed_password, full_name, now))
    mydb.commit()

    user_id = cursor.lastrowid

    query = "INSERT INTO user_details (coin_count, user_id) VALUES (%s, %s)"
    cursor.execute(query, (2, user_id))
    mydb.commit()
    # Generate JWT token for the new user
    token = jwt.encode({'username': email, 'exp': datetime.datetime.max},
                       app.config['SECRET_KEY'])
    response_data = {'id': user_id, "token": token}
    response = make_response(jsonify(response_data))
    return response, 201


@app.route('/requiredInformations', methods=['POST'])
@jwt_required
def update_user_info():
    # Get the user ID and information from the request body
    user_id = request.json.get('userId')
    job = request.json.get('job')
    relationship = request.json.get('relationship')
    gender = request.json.get('gender')
    birthDate = request.json.get('birthDate')

    # Check if all fields are provided
    if user_id is None or job is None or relationship is None or gender is None or birthDate is None:
        return jsonify({'errorMessage': 'All fields (job, relationship, gender, birthDate) are required!'}), 400

    # Connect to the database
    cursor = mydb.cursor()

    # Execute a parameterized query to update the job, relationship, and gender fields for the specified user
    query = "UPDATE user_details SET job = %s, relationship = %s, gender = %s, date_of_birth = %s WHERE user_id = %s"
    cursor.execute(query, (job, relationship, gender,birthDate, user_id))

    # Commit the changes to the database
    mydb.commit()

    # Close the database connection
    cursor.close()

    # Return a success message
    return jsonify({'message': 'User information updated successfully!'})


class ChooseModal:
    def __init__(self, coinCount, selectedInterpreterName, selectedItemIndex, interPreptType):
        self.coinCount = coinCount
        self.selectedInterpreterName = selectedInterpreterName
        self.selectedItemIndex = selectedItemIndex
        self.interPreptType = interPreptType


@app.route('/sendDreams', methods=['POST'])
def sendDreams():
    # Parse request data
    data = request.get_json()
    userID = data.get("userID")
    dream = data.get("dream")
    religious = data.get("religious")
    psychological = data.get("psycological")
    pushToken = data.get("devicePushToken")

    # Handle the chosenDreamer object
    chosenDreamer_data = data.get("chosenDreamer")
    chosenDreamer = ChooseModal(
        coinCount=chosenDreamer_data.get("coinCount"),
        selectedInterpreterName=chosenDreamer_data.get("selectedInterpreterName"),
        selectedItemIndex=chosenDreamer_data.get("selectedItemIndex"),
        interPreptType=chosenDreamer_data.get("InterPreptType")
    )
    status = 0
    if religious == True and psychological == True:
        # ikisi birlikte yorumla
        status = 0
    elif religious == True and psychological == False:
        # dini yorumla
        status = 1
    elif religious == False and psychological == True:
        # psikolojik yorumla
        status = 2
    else:
        # ikisinide seçme
        status = 3
    # Use a cursor to fetch the coin_count
    cursor = mydb.cursor()
    cursor.execute("SELECT coin_count FROM user_details WHERE user_id = %s", (userID,))
    user_details = cursor.fetchone()
    # Check if coinCount is less than coin_count
    if chosenDreamer.coinCount is not None and chosenDreamer.coinCount > user_details[0]:
        return jsonify({'error': 'You do not have enough coins for interprept this dream'}), 400

        # Get the current date in the format 'YYYY-MM-DD'
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')

    # Insert the data into the UserDreams table
    insert_query = "INSERT INTO UserDreams (userId, dreamInformation, dreamStatus, dreamDate, UsedCoin, InterPreptType, dreamResult, dreamType, pushToken) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    cursor.execute(insert_query,
                   (userID, dream, 0, current_date, chosenDreamer.coinCount, chosenDreamer.interPreptType, None, status,
                    pushToken))

    # Commit the transaction and close the cursor and database connection
    mydb.commit()
    # Update the coinCount in user_details table
    update_query = "UPDATE user_details SET coin_count = %s WHERE user_id = %s"
    cursor.execute(update_query, (user_details[0] - chosenDreamer.coinCount, userID))
    mydb.commit()
    cursor.close()

    return jsonify({'message': 'Your dream has been successfully sent for interpretation.'})


@app.route('/updateCoin', methods=['POST'])
@jwt_required
def update_coin():
    # POST isteğinden veriyi al
    data = request.get_json()
    # Gerekli verileri al
    userID = data.get('userID')
    coinType = data.get('coinType')
    desiredCoin = convert_to_coin(coinType)

    # Eğer userID veya coinType verisi eksikse, hata döndür
    if userID is None or coinType is None:
        return jsonify({'errorMessage': 'userID and coinType are required parameters.'}), 400

    cursor = mydb.cursor()
    # Veritabanında coin_count güncelleniyor
    # Mevcut coin sayısını al
    cursor.execute("SELECT coin_count FROM user_details WHERE user_id = %s", (userID,))
    currentCoinCount = cursor.fetchone()[0]
    updatedCoinCount = currentCoinCount + desiredCoin

    update_query = "UPDATE user_details SET coin_count = %s WHERE (user_id = %s)"
    cursor.execute(update_query, (updatedCoinCount, userID))
    mydb.commit()
    # Güncelleme işlemi başarılıysa, güncellenmiş coin sayısını responseda döndür
    if cursor.rowcount > 0:
        response_data = {
            'message': 'Coin updated successfully.',
            'updatedCoinCount': updatedCoinCount
        }
    else:
        response_data = {
            'message': 'Failed to update coin count.'
        }
        # Cursor'ı kapat
    cursor.close()

    return jsonify(response_data), 200


def convert_to_coin(value):
    coin = None
    switch = {
        0: 20,
        1: 50,
        2: 100,
        3: 150,
        4: 200,
        5: 500
    }
    coin = switch.get(value)
    return coin


# .p8 dosyasından anahtar okuma fonksiyonu
def read_p8_key(file_path):
    with open(file_path, 'r') as file:
        key = file.read()
    key = key.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")
    # Boşlukları kaldır
    key = key.replace("\n", "")
    # Base64 kodlama
    encoded_key = base64.b64encode(key.encode("utf-8")).decode("utf-8")

    return key


@app.route('/send-push-notification', methods=['POST'])
def send_push_notification():
    # Gelen isteğin doğrulanması
    myData = request.get_json()
    devicePushToken = myData.get('pushToken')
    dream_id = myData.get('dreamId')
    user_id = myData.get('userId')
    dream_result = myData.get('dreamResult')
    # Eğer dreamId veya userId yoksa hata döndür
    if not dream_id or not user_id:
        return jsonify({'Message': 'dreamId or userId parameter is missing'}), 400
    mydb = get_db()
    cursor = mydb.cursor()
    # DreamStatus ve DreamResult güncellemesi için SQL sorgusu
    query = """ UPDATE UserDreams SET dreamStatus = 1, dreamResult = %s WHERE dreamid = %s AND userId = %s """
    # Sorguyu çalıştır
    cursor.execute(query, (dream_result, dream_id, user_id))

    # Veritabanı değişikliklerini kaydet
    mydb.commit()
    # Veritabanı bağlantısını kapat
    cursor.close()
    # FCM API Key
    fcm_api_key = 'AAAALK_cgdQ:APA91bFKt1ttQ6pikbDpV5S8bruDi1C3JwEGQPzBhJN0JCiXOR90jQUlsiBOs_H86DUSB-z-qIp0ncrE4hded5XWZCTSOvtAa4OFvFj7haNebPfdAnq1vpFPI8uc8N3SoCAY0mlAYXXI'
    # Push bildirimi verisi
    accept_language = request.headers.get('Accept-Language')
    bodyTitle = "Your Dream has been interpreted, see what happened now!"
    title = "Your Dream has been interpreted."
    if accept_language == "tr":
        bodyTitle = "Rüyan yorumlandı hemen ne olduğuna bak!"
        title = "Rüyan Yorumlandı."

    data = {
        "message": {
            "token": devicePushToken,
            "notification": {
                "body": bodyTitle,
                "title": title
            }
        }
    }

    # FCM HTTP API'ye istek gönderme
    headers = {
        'Authorization': 'Bearer ' + _get_access_token(),
        'Content-Type': 'application/json; UTF-8'

    }
    response = requests.post('https://fcm.googleapis.com/v1/projects/dreamly2/messages:send', json=data,
                             headers=headers)
    # Yanıtı kontrol etme
    if response.status_code == 200:
        return jsonify({'success': True, 'message': 'Push notification sent successfully.'}), 200
    else:
        return jsonify(
            {'success': False, 'error': 'Failed to send push notification.', 'status_code': response.status_code}), 500


def _get_access_token():
    credentials = service_account.Credentials.from_service_account_file(
        app.config["Service"], scopes=SCOPES)

    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    return credentials.token


@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    data = request.get_json()
    userID = data.get("userId")
    token = data.get("token")

    if userID != None and token != None:
        return jsonify({'message': 'user loggedout!'})
    else:
        return jsonify({'error': 'user couldnt loggedout'}), 400

# deleteUser endpoint'i
@app.route('/deleteUser', methods=['POST'])
@jwt_required
def delete_user():
    data = request.get_json()
    userID = data.get("userId")

    if userID:
        cursor = mydb.cursor()

        # UserDreams tablosundan kullanıcıya ait kayıtları silme
        cursor.execute("DELETE FROM UserDreams WHERE userId = %s", (userID,))
        # user_details tablosundan kullanıcıya ait kayıtları silme
        cursor.execute("DELETE FROM user_details WHERE user_id = %s", (userID,))
        # Users tablosundan kullanıcıya ait kayıtları silme
        cursor.execute("DELETE FROM Users WHERE id = %s", (userID,))

        mydb.commit()
        cursor.close()

        return jsonify({'message': 'All your user data removed from our system!'})
    else:
        return jsonify({'message': 'Userid is missing'}), 400

@app.route('/checkUserDetails', methods=['POST'])
def check_user_details():
    data = request.get_json()
    userID = data.get("userId")

    if userID:
        cursor = mydb.cursor()

        # user_details tablosundan kullanıcı detaylarını al
        cursor.execute("SELECT * FROM user_details WHERE user_id = %s", (userID,))
        user_details = cursor.fetchone()

        if user_details:
            # Kullanıcı detaylarını kontrol et
            print(user_details[0])
            is_details_full = user_details[1] is not None or user_details[2] is not None or user_details[3] is not None or user_details[4] is not None
            return jsonify({'isUserDetailsAreFull': is_details_full})
        else:
            return jsonify({'message': 'Kullanıcı detayları bulunamadı'}), 404
    else:
        return jsonify({'message': 'Kullanıcı kimliği eksik'}), 400

@app.route('/emptyRequest')
def empty_request():
    return jsonify({'message': 'Server is up and running!'})

# Flask endpoint'i
@app.route('/getAllDreamsForInterprept', methods=['POST'])
def getAllDreamsForInterprept():
    try:
        # Veritabanı bağlantısını al
        mydb = get_db()
        cursor = mydb.cursor()

        # SQL sorgusu
        query = """
            SELECT 
                Users.fullName,
                Users.id,
                UserDreams.dreamid,
                UserDreams.dreamInformation,
                UserDreams.dreamStatus,
                UserDreams.dreamDate,
                UserDreams.UsedCoin,
                UserDreams.InterpreptType,
                UserDreams.dreamResult,
                UserDreams.pushToken,
                user_details.relationship,
                user_details.gender,
                user_details.coin_count,
                user_details.Job
            FROM 
                UserDreams
            INNER JOIN 
                Users ON UserDreams.userId = Users.id
            INNER JOIN 
                user_details ON UserDreams.userId = user_details.user_id
            WHERE 
                UserDreams.dreamStatus = 0
        """

        # Sorguyu çalıştır
        cursor.execute(query)
        data = cursor.fetchall()

        # Veritabanı bağlantısını kapat
        cursor.close()

        # Sonuçları JSON formatında döndür
        dreams = []
        for row in data:
            dream = {
                'fullName': row[0],
                'userId': row[1],
                'dreamId': row[2],
                'dreamInformation': row[3],
                'dreamStatus': row[4],
                'dreamDate': row[5],
                'usedCoin': row[6],
                'interpreptType': row[7],
                'dreamResult': row[8],
                'pushToken': row[9],
                'relationship': row[10],
                'gender': row[11],
                'coinCount': row[12],
                'job': row[13]
            }
            dreams.append(dream)

        return jsonify({'dreams': dreams})

    except Exception as e:
        return jsonify({'message': 'dream datalarını çekerken sorun oluştu'}), 400

if __name__ == '__main__':
    cred = credentials.Certificate(app.config["Service"])
    firebase_admin.initialize_app(cred)
    app.run(host="0.0.0.0", port=5000, debug=True)

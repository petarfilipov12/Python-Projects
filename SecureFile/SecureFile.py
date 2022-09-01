import hashlib
import base64
from PyQt5.QtCore import QSize
from PyQt5.QtWidgets import QWidget, QPushButton, QLineEdit, QVBoxLayout, QMessageBox, QPlainTextEdit, QToolBar, QToolButton, QMainWindow, QApplication
from Crypto.Cipher import AES

FILE = "data"
PASSWORD_HASH_FILE = "passhash"

DEBUG = True


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.key = ""
        self.nonce = ""
        self.PASSWORD_HASH = ""
        self.text = ""

        try:
            self.PASSWORD_HASH = self.GetPassHash()
            
            if(self.PASSWORD_HASH == "" or self.PASSWORD_HASH == None):
                self.InItWindow()
            else:
                self.LogInWindow()
        except FileNotFoundError:
            self.InItWindow()


    def GetPassHash(self):
        global PASSWORD_HASH_FILE
        
        f = open(PASSWORD_HASH_FILE, "r")
        passhash = f.read()
        f.close()

        return passhash

    def SetPassHash(self, passhash):
        global PASSWORD_HASH_FILE
        
        f = open(PASSWORD_HASH_FILE, "w")
        f.write(passhash)
        f.close()

    def InItWindow(self):
        self.setMinimumSize(QSize(400, 300))
        self.resize(QSize(400, 300))
        
        button = QPushButton("Submit")
        button.clicked.connect(self.init_submit_button_was_clicked)
        
        self.init_pass_input_text = QLineEdit()
        self.init_pass_input_text.setPlaceholderText("Password")
        self.init_pass_input_text.setEchoMode(QLineEdit.Password)

        self.init_confirm_pass_input_text = QLineEdit()
        self.init_confirm_pass_input_text.setPlaceholderText("Confirm Pass")
        self.init_confirm_pass_input_text.setEchoMode(QLineEdit.Password)

        layout = QVBoxLayout()
        layout.addWidget(self.init_pass_input_text)
        layout.addWidget(self.init_confirm_pass_input_text)
        layout.addWidget(button)

        container = QWidget()
        container.setLayout(layout)

        self.setCentralWidget(container)

    def init_submit_button_was_clicked(self):
        password = self.init_pass_input_text.text()
        confpass = self.init_confirm_pass_input_text.text()

        if(password != confpass):
            msg = QMessageBox()
            msg.setWindowTitle("SecureFile")
            msg.setText("Password and Confirm Password must match!")
            msg.setIcon(QMessageBox.Critical)
            msg.exec_()
        else:
            self.PASSWORD_HASH = hashlib.sha256(password.encode()).hexdigest()
            self.SetPassHash(passhash = self.PASSWORD_HASH)
            
            self.LogInWindow()
        
    def LogInWindow(self):
        self.setWindowTitle("SecureFile")
        self.setMinimumSize(QSize(400, 300))
        
        self.button = QPushButton("Log In")
        self.button.clicked.connect(self.the_login_button_was_clicked)
        
        self.input_text = QLineEdit()
        self.input_text.returnPressed.connect(self.the_login_button_was_clicked)
        self.input_text.setEchoMode(QLineEdit.Password)

        layout = QVBoxLayout()
        layout.addWidget(self.input_text)
        layout.addWidget(self.button)

        container = QWidget()
        container.setLayout(layout)

        self.setCentralWidget(container)
        
    def the_login_button_was_clicked(self):
        password = self.input_text.text()

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if(password_hash == self.PASSWORD_HASH):
            (self.key, self.nonce) = self.GetKeyAndNonce(password=password)

            self.EditTextWindow()
        else:
            msg = QMessageBox()
            msg.setWindowTitle("SecureFile")
            msg.setText("Wrong password!")
            msg.setIcon(QMessageBox.Critical)
            msg.exec_()

    def GetKeyAndNonce(self, password):
        key = hashlib.blake2s(password.encode()).digest()
        nonce = hashlib.md5(password.encode()).digest()

        return (key, nonce)
    
    def EditTextWindow(self):
        self.setMinimumSize(QSize(800, 600))
        
        self.PlainText = QPlainTextEdit()
        text = self.ReadTextFromEncryptedFile()
        self.PlainText.appendPlainText(text)

        toolBar = QToolBar()
        toolButton = QToolButton()
        toolButton.setText("Save")
        toolButton.clicked.connect(self.save_button_was_clicked)
        toolBar.addWidget(toolButton)
        
        toolButton = QToolButton()
        toolButton.setText("Change Pass")
        toolButton.clicked.connect(self.change_pass_button_was_clicked)
        toolBar.addWidget(toolButton)

        layout = QVBoxLayout()
        layout.addWidget(toolBar)
        layout.addWidget(self.PlainText)

        container = QWidget()
        container.setLayout(layout)

        # Set the central widget of the Window.
        self.setCentralWidget(container)

    def ReadTextFromEncryptedFile(self):
        global FILE
        global DEBUG
        text = ""
        
        try:
            f = open(FILE, "r")
            encrypted_text = f.read()
            f.close()

            cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
            encrypted_text = base64.b64decode(encrypted_text)
            text = cipher.decrypt(encrypted_text)
            text = text.decode()

            if(DEBUG == True):
                print(text)
        except Exception as e:
            if(DEBUG == True):
                print(e)

        return text

    def save_button_was_clicked(self):
        try:
            text = self.PlainText.toPlainText()
            encrypted_text = self.EncryptText(text = text)

            self.SaveTextToFile(text = encrypted_text)
        except Exception as e:
            global DEBUG
            if(DEBUG == True):
                print(e)

    def EncryptText(self, text): 
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        encrypted_text, tag = cipher.encrypt_and_digest(text.encode())
        encrypted_text = base64.b64encode(encrypted_text).decode()

        return encrypted_text
        
    def SaveTextToFile(self, text):
        global FILE

        f = open(FILE, "w")
        f.write(text)
        f.close()

    def change_pass_button_was_clicked(self):
        self.data_text = self.PlainText.toPlainText()
        self.ChangePassWindow()

    def ChangePassWindow(self):
        self.setMinimumSize(QSize(400, 300))
        self.resize(QSize(400, 300))

        toolBar = QToolBar()
        toolButton = QToolButton()
        toolButton.setText("Back")
        toolButton.clicked.connect(self.back_button_was_clicked)
        toolBar.addWidget(toolButton)
        
        button = QPushButton("Submit")
        button.clicked.connect(self.submit_button_was_clicked)
        
        self.current_pass_input_text = QLineEdit()
        self.current_pass_input_text.setPlaceholderText("Current Pass")
        self.current_pass_input_text.setEchoMode(QLineEdit.Password)
        
        self.new_pass_input_text = QLineEdit()
        self.new_pass_input_text.setPlaceholderText("New Pass")
        self.new_pass_input_text.setEchoMode(QLineEdit.Password)

        self.confirm_pass_input_text = QLineEdit()
        self.confirm_pass_input_text.setPlaceholderText("Confirm Pass")
        self.confirm_pass_input_text.setEchoMode(QLineEdit.Password)

        layout = QVBoxLayout()
        layout.addWidget(toolBar)
        layout.addWidget(self.current_pass_input_text)
        layout.addWidget(self.new_pass_input_text)
        layout.addWidget(self.confirm_pass_input_text)
        layout.addWidget(button)

        container = QWidget()
        container.setLayout(layout)

        self.setCentralWidget(container)

    def back_button_was_clicked(self):
        self.Window2()
        
    def submit_button_was_clicked(self):
        password = self.current_pass_input_text.text()

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if(password_hash != self.PASSWORD_HASH):
            msg = QMessageBox()
            msg.setWindowTitle("SecureFile")
            msg.setText("Wrong Current password!")
            msg.setIcon(QMessageBox.Critical)
            msg.exec_()
        else:
            newpass = self.new_pass_input_text.text()
            confpass = self.confirm_pass_input_text.text()
            
            if(newpass != confpass):
                msg = QMessageBox()
                msg.setWindowTitle("SecureFile")
                msg.setText("New Password and Confirm Password must match!")
                msg.setIcon(QMessageBox.Critical)
                msg.exec_()
            else:
                self.ChangePassword(newpass = newpass)

    def ChangePassword(self, newpass):
        self.PASSWORD_HASH = hashlib.sha256(newpass.encode()).hexdigest()
        self.SetPassHash(passhash = self.PASSWORD_HASH)

        (self.key, self.nonce) = self.GetKeyAndNonce(password=newpass)
        try:
            text = self.data_text
            encrypted_text = self.EncryptText(text = text)

            self.SaveTextToFile(text = encrypted_text)
        except Exception as e:
            global DEBUG
            if(DEBUG == True):
                print(e)

        self.EditTextWindow()
       
            
if (__name__ == "__main__"):
    app = QApplication([])

    window = MainWindow()
    window.show()

    app.exec()



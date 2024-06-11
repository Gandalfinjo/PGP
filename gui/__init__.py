from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QMainWindow, QDialog, QFileDialog

from gui.main_window import Ui_MainWindow
from gui.generate_key_pair import Ui_GenerateKeyPairDialog
from gui.send_message import Ui_SendMessageDialog


class PGPApp(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.generateKeyPairDialog = None
        self.sendMessageDialog = None
        self.setupUi(self)
        self.setup_connections()

    def setup_connections(self):
        self.generateButton.clicked.connect(self.open_generate_key_pair_dialog)
        self.sendButton.clicked.connect(self.open_send_message_dialog)

    def open_generate_key_pair_dialog(self):
        self.generateKeyPairDialog = GenerateKeyPairDialog(self)
        self.generateKeyPairDialog.keyPairGenerated.connect(self.generate_key_pair)
        self.generateKeyPairDialog.exec_()
        self.generateKeyPairDialog = None

    def open_send_message_dialog(self):
        self.sendMessageDialog = SendMessageDialog(self)
        self.sendMessageDialog.messageCreated.connect(self.send_message)
        self.sendMessageDialog.exec_()
        self.sendMessageDialog = None

    def generate_key_pair(self, name, email, keySize, password):
        if password is None or password == "":
            self.statusbar.showMessage(f"Missing password", 4000)
            return

        print(f"Name: {name}, Email: {email}, Key size: {keySize}, Password: {password}")

    def send_message(self, publicKey, privateKey, algorithm, message):
        print(f"Public key: {publicKey}, Private key: {privateKey}, Encryption algorithm: {algorithm}, Message: {message}")


class GenerateKeyPairDialog(QDialog, Ui_GenerateKeyPairDialog):
    keyPairGenerated = pyqtSignal(str, str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setup_connections()

    def setup_connections(self):
        self.buttonBox.accepted.connect(self.on_accept)

    def on_accept(self):
        name = self.nameLineEdit.text()
        email = self.emailLineEdit.text()
        keySize = self.comboBox.currentText()
        password = self.passLineEdit.text()

        self.keyPairGenerated.emit(name, email, keySize, password)
        self.accept()


class SendMessageDialog(QDialog, Ui_SendMessageDialog):
    messageCreated = pyqtSignal(str, str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setup_connections()
        self.privateComboBox.clear()
        self.publicComboBox.clear()

    def setup_connections(self):
        self.buttonBox.accepted.connect(self.on_accept)

    def on_accept(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        filePath, _ = QFileDialog.getSaveFileName(
            self,
            "Choose the message location",
            "",
            "Message Files (*.msg);;All Files(*)",
            options=options
        )

        if filePath is None or filePath == "":
            return

        encrypt = self.encryptionCheckBox.isChecked()
        sign = self.signCheckBox.isChecked()
        compress = self.compressCheckBox.isChecked()
        convertR64 = self.convertCheckBox.isChecked()
        message = self.messageText.toPlainText()

        publicKey = ""
        privateKey = ""
        algorithm = self.algorithmComboBox.currentText()

        if encrypt:
            publicKey = self.publicComboBox.currentText()
        if sign:
            privateKey = self.privateComboBox.currentText()

        self.messageCreated.emit(publicKey, privateKey, algorithm, message)
        self.accept()

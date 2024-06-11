from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QMainWindow, QDialog

from gui.main_window import Ui_MainWindow
from gui.generate_key_pair import Ui_GenerateKeyPairDialog


class PGPApp(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.generateKeyPairDialog = None
        self.setupUi(self)
        self.setup_connections()

    def setup_connections(self):
        self.generateButton.clicked.connect(self.open_generate_key_pair_dialog)

    def open_generate_key_pair_dialog(self):
        self.generateKeyPairDialog = GenerateKeyPairDialog(self)
        self.generateKeyPairDialog.keyPairGenerated.connect(self.generate_key_pair)
        self.generateKeyPairDialog.exec_()
        self.generateKeyPairDialog = None

    def generate_key_pair(self, name, email, keySize, password):
        if password is None or password == "":
            self.statusbar.showMessage(f"Missing password", 4000)
            return

        print(f"Name: {name}, Email: {email}, Key size: {keySize}, Password: {password}")


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

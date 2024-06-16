import zlib
from base64 import b64encode
from datetime import datetime

from Crypto.Cipher import PKCS1_OAEP, AES, DES3
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QMainWindow, QDialog, QFileDialog

from core.keyring import Keyring

from gui.main_window import Ui_MainWindow
from gui.generate_key_pair import Ui_GenerateKeyPairDialog
from gui.delete_key_pair import Ui_DeleteKeyPairDialog
from gui.import_key import Ui_ImportKeyDialog
from gui.export_key import Ui_ExportKeyDialog
from gui.send_message import Ui_SendMessageDialog
from gui.receive_message import Ui_ReceiveMessageDialog


class PGPApp(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.key_sizes = [1024, 2048]
        self.generateKeyPairDialog = None
        self.deleteKeyPairDialog = None
        self.importDialog = None
        self.exportDialog = None
        self.sendMessageDialog = None
        self.receiveMessageDialog = None
        self.keyring = Keyring()
        self.setupUi(self)
        self.setup_connections()
        self.load_private_keys()
        self.load_public_keys()

    def setup_connections(self):
        self.generateButton.clicked.connect(self.open_generate_key_pair_dialog)
        self.actionGenerate.triggered.connect(self.open_generate_key_pair_dialog)

        self.deleteButton.clicked.connect(self.open_delete_key_pair_dialog)
        self.actionDelete.triggered.connect(self.open_delete_key_pair_dialog)

        self.importButton.clicked.connect(self.open_import_key_dialog)
        self.actionImport.triggered.connect(self.open_import_key_dialog)

        self.exportButton.clicked.connect(self.open_export_key_dialog)
        self.actionExport.triggered.connect(self.open_export_key_dialog)

        self.sendButton.clicked.connect(self.open_send_message_dialog)
        self.actionSend.triggered.connect(self.open_send_message_dialog)

        self.receiveButton.clicked.connect(self.open_receive_message_dialog)
        self.actionReceive.triggered.connect(self.open_receive_message_dialog)

    def load_private_keys(self):
        keys = self.keyring.get_private_keys()
        self.privateTableWidget.setRowCount(len(keys))
        for i in range(len(keys)):
            self.privateTableWidget.setItem(i, 0, QtWidgets.QTableWidgetItem(keys[i]["name"]))
            self.privateTableWidget.setItem(i, 1, QtWidgets.QTableWidgetItem(keys[i]["email"]))
            self.privateTableWidget.setItem(i, 2, QtWidgets.QTableWidgetItem(str(keys[i]["key_size"])))
            self.privateTableWidget.setItem(i, 3, QtWidgets.QTableWidgetItem(keys[i]["key_id"][2:]))

        # self.privateTableWidget.clearContents()
        # path = "data/private_keys/private_keyring.json"
        #
        # if os.path.exists(path) and os.path.getsize(path) > 0:
        #     with open(path, "r") as file:
        #         keys = json.load(file)
        #
        #     self.privateTableWidget.setRowCount(len(keys))
        #     for i in range(len(keys)):
        #         self.privateTableWidget.setItem(i, 0, QtWidgets.QTableWidgetItem(keys[i]["name"]))
        #         self.privateTableWidget.setItem(i, 1, QtWidgets.QTableWidgetItem(keys[i]["email"]))
        #         self.privateTableWidget.setItem(i, 2, QtWidgets.QTableWidgetItem(str(keys[i]["key_size"])))
        #         self.privateTableWidget.setItem(i, 3, QtWidgets.QTableWidgetItem(keys[i]["key_id"][2:]))

    def load_public_keys(self):
        keys = self.keyring.get_public_keys()
        self.publicTableWidget.setRowCount(len(keys))
        for i in range(len(keys)):
            self.publicTableWidget.setItem(i, 0, QtWidgets.QTableWidgetItem(keys[i]["name"]))
            self.publicTableWidget.setItem(i, 1, QtWidgets.QTableWidgetItem(keys[i]["email"]))
            self.publicTableWidget.setItem(i, 2, QtWidgets.QTableWidgetItem(str(keys[i]["key_size"])))
            self.publicTableWidget.setItem(i, 3, QtWidgets.QTableWidgetItem(keys[i]["key_id"][2:]))

            # self.publicTableWidget.setRowCount(len(keys))
            # for i, item in enumerate(keys):
            #     for j, value in enumerate(item.values()):
            #         self.publicTableWidget.setItem(i, j, QtWidgets.QTableWidgetItem(str(value)))

    def open_generate_key_pair_dialog(self):
        self.generateKeyPairDialog = GenerateKeyPairDialog(self)
        self.generateKeyPairDialog.keyPairGenerated.connect(self.generate_key_pair)
        self.generateKeyPairDialog.exec_()
        self.generateKeyPairDialog = None

    def open_delete_key_pair_dialog(self):
        keys = self.keyring.get_private_keys()
        if not keys:
            keys = self.keyring.get_public_keys()

        self.deleteKeyPairDialog = DeleteKeyPairDialog(keys, self)
        self.deleteKeyPairDialog.keyPairChosen.connect(self.delete_key_pair)
        self.deleteKeyPairDialog.exec_()
        self.generateKeyPairDialog = None

    def open_import_key_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        filePath, _ = QFileDialog.getOpenFileName(
            self,
            "Choose the key file",
            "",
            "PEM Files (*.pem);;All Files(*)",
            options=options
        )

        if filePath is None or filePath == "":
            return

        self.importDialog = ImportDialog(self)
        self.importDialog.keyImported.connect(lambda name, email, passphrase: self.import_key(filePath, name, email, passphrase))
        self.importDialog.exec_()
        self.importDialog = None

    def open_export_key_dialog(self):
        self.exportDialog = ExportKeyDialog(self.keyring.get_private_keys(), self)
        self.exportDialog.keyExported.connect(self.export_key)
        self.exportDialog.exec_()
        self.exportDialog = None

    def open_send_message_dialog(self):
        self.sendMessageDialog = SendMessageDialog(self.keyring.get_private_keys(), self.keyring.get_public_keys(), self)
        self.sendMessageDialog.messageCreated.connect(self.send_message)
        self.sendMessageDialog.exec_()
        self.sendMessageDialog = None

    def open_receive_message_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        filePath, _ = QFileDialog.getOpenFileName(
            self,
            "Choose the message file",
            "",
            "Message Files (*.msg);;All Files(*)",
            options=options
        )

        if filePath is None or filePath == "":
            return

        self.receiveMessageDialog = ReceiveMessageDialog(self)

        with open(filePath, "r") as file:
            self.receiveMessageDialog.messageText.setPlainText(file.read())

        self.receiveMessageDialog.messageSaved.connect(self.receive_message)
        self.receiveMessageDialog.exec_()
        self.receiveMessageDialog = None

    def generate_key_pair(self, name, email, key_size, password):
        if password is None or password == "":
            self.statusbar.showMessage(f"Missing password", 4000)
            return

        private_key, public_key = self.keyring.generate_key_pair(name, email, self.key_sizes[key_size], password)
        self.load_private_keys()
        self.load_public_keys()

        # print(f"Name: {name}, Email: {email}, Key size: {self.key_sizes[key_size]}, Password: {password}")
        # print(f"Private key: {private_key}, Public key: {public_key}")

    def delete_key_pair(self, key_id):
        keys = self.keyring.get_private_keys()

        if not keys:
            keys = self.keyring.get_public_keys()
            if not keys:
                self.statusbar.showMessage("No keys available for deletion", 4000)
                return

        self.keyring.delete_key_pair(key_id)
        self.load_private_keys()
        self.load_public_keys()

    def import_key(self, filePath, name, email, passphrase):
        try:
            with open(filePath, "r") as file:
                key_data = file.read()

            if "PRIVATE KEY" in key_data:
                key_parts = key_data.split("-----END RSA PRIVATE KEY-----")
                key_parts[0] += "-----END RSA PRIVATE KEY-----"
                key_parts[1].strip()

                private_key_part = key_parts[0]
                public_key_part = key_parts[1]

                choice, ok = QtWidgets.QInputDialog.getItem(
                    self, "Import Key", "Choose part/s to import:",
                    ["Public Key Only", "Whole Key Pair"], 0, False
                )

                if not ok:
                    return

                if choice == "Whole Key Pair":
                    try:
                        key = RSA.import_key(private_key_part, passphrase=passphrase)
                        private_key = key.export_key(passphrase=passphrase).decode()
                        public_key = key.public_key().export_key().decode()
                        key_id = self.keyring.calculate_key_id(key)
                        key_size = key.size_in_bits()
                        timestamp = datetime.now().isoformat()

                        private_key_entry = {
                            "name": name,
                            "email": email,
                            "key_size": key_size,
                            "key_id": key_id,
                            "private_key": private_key,
                            "public_key": public_key,
                            "timestamp": timestamp
                        }

                        public_key_entry = {
                            "name": name,
                            "email": email,
                            "key_size": key_size,
                            "key_id": key_id,
                            "public_key": public_key,
                            "timestamp": timestamp
                        }

                        self.keyring.private_keyring.append(private_key_entry)
                        self.keyring.public_keyring.append(public_key_entry)

                        self.keyring.save_keyring(self.keyring.private_keyring_path, self.keyring.private_keyring)
                        self.keyring.save_keyring(self.keyring.public_keyring_path, self.keyring.public_keyring)

                        self.load_private_keys()
                        self.load_public_keys()
                    except ValueError:
                        QtWidgets.QMessageBox.warning(self, "Invalid Passphrase", "The passphrase is incorrect. Please try again.")
                        return
                else:
                    key = RSA.import_key(private_key_part, passphrase=passphrase)
                    public_key = key.public_key().export_key().decode()
                    key_id = self.keyring.calculate_key_id(key)
                    key_size = key.size_in_bits()
                    timestamp = datetime.now().isoformat()

                    public_key_entry = {
                        "name": name,
                        "email": email,
                        "key_size": key_size,
                        "key_id": key_id,
                        "public_key": public_key,
                        "timestamp": timestamp
                    }

                    self.keyring.public_keyring.append(public_key_entry)
                    self.keyring.save_keyring(self.keyring.public_keyring_path, self.keyring.public_keyring)
                    self.load_public_keys()
            else:
                key = RSA.import_key(key_data)
                public_key = key.public_key().export_key().decode()
                key_id = self.keyring.calculate_key_id(key)
                key_size = key.size_in_bits()
                timestamp = datetime.now().isoformat()

                public_key_entry = {
                    "name": name,
                    "email": email,
                    "key_size": key_size,
                    "key_id": key_id,
                    "public_key": public_key,
                    "timestamp": timestamp
                }

                self.keyring.public_keyring.append(public_key_entry)
                self.keyring.save_keyring(self.keyring.public_keyring_path, self.keyring.public_keyring)
                self.load_public_keys()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"An error occured: {e}")

    def export_key(self, key_id, onlyPublic, wholePair, filePath):
        key = self.keyring.export_key(key_id, wholePair)

        if wholePair:
            passphrase, ok = QtWidgets.QInputDialog.getText(self, "Passphrase", "Enter passphrase:", QtWidgets.QLineEdit.Password)

            if not ok:
                return

            try:
                RSA.import_key(key["private_key"], passphrase=passphrase)
            except ValueError:
                QtWidgets.QMessageBox.warning(self, "Invalid Passphrase", "The passphrase is incorrect. Please try again.")
                return

        with open(filePath, "w") as file:
            if onlyPublic:
                file.write(key["public_key"])
            elif wholePair:
                file.write(key["private_key"])
                file.write("\n")
                file.write(key["public_key"])

    def send_message(self, public_key_id: str, private_key_id: str, algorithm: str, message: str, compress, convertR64, filePath):
        encrypted_ks = ""
        try:
            public_key = None
            if public_key_id:
                public_key_entry = next((key for key in self.keyring.get_public_keys() if key["key_id"] == public_key_id), None)
                if public_key_entry:
                    public_key = RSA.import_key(public_key_entry["public_key"])

            private_key = None
            if private_key_id:
                private_key_entry = next((key for key in self.keyring.get_private_keys() if key["key_id"] == private_key_id), None)
                if private_key_entry:
                    passphrase, ok = QtWidgets.QInputDialog.getText(self, "Passphrase", "Enter passphrase:", QtWidgets.QLineEdit.Password)

                    if not ok:
                        return

                    try:
                        private_key = RSA.import_key(private_key_entry["private_key"], passphrase=passphrase)
                    except ValueError:
                        QtWidgets.QMessageBox.warning(self, "Invalid Passphrase", "The passphrase is incorrect. Please try again.")
                        return

            if private_key:
                h = SHA1.new(message.encode())
                signature = str(pkcs1_15.new(private_key).sign(h))[2:-1]
                timestamp = datetime.now().isoformat()

                signed_message = message + "\n" + signature + "\n" + private_key_id + "\n" + timestamp
            else:
                signed_message = message

            if public_key:
                rsa_cipher = PKCS1_OAEP.new(public_key)
                session_key = get_random_bytes(16 if algorithm == "AES128" else 24)

                if algorithm == "AES-128":
                    symmetric_cipher = AES.new(session_key, AES.MODE_CFB)
                elif algorithm == "Triple DES":
                    symmetric_cipher = DES3.new(session_key, DES3.MODE_CFB)
                else:
                    raise ValueError("Unsupported algorithm")

                ciphertext = str(symmetric_cipher.encrypt(pad(signed_message.encode(), AES.block_size)))[2:-1]
                encrypted_ks = str(rsa_cipher.encrypt(session_key))[2:-1]
                iv = symmetric_cipher.iv
                timestamp = datetime.now().isoformat()

                encrypted_message = ciphertext + "\n" + timestamp
                print("----------------------------------------------------\n")
                print(encrypted_message)
            else:
                encrypted_message = signed_message

            if compress:
                encrypted_message = str(zlib.compress(encrypted_message.encode()))[2:-1]
                print("-----------------------------------\n")
                print(encrypted_message)

            encrypted_message += encrypted_ks
            print("------------------------\n")
            print(encrypted_message)
            encrypted_message += public_key_id
            print("------------------------\n")
            print(encrypted_message)

            if convertR64:
                encrypted_message = b64encode(encrypted_message.encode()).decode()
                print("------------------------\n")
                print(encrypted_message)

            with open(filePath, "w") as file:
                file.write(encrypted_message)

            self.statusbar.showMessage(f"Message saved to {filePath}", 4000)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"An error occurred: {e}")

        # print(f"Public key: {public_key_id}, Private key: {private_key_id}")
        # print(f"Encryption algorithm: {algorithm}, Message: {message}")

    def receive_message(self, message):
        print(f"Message: {message}")


class GenerateKeyPairDialog(QDialog, Ui_GenerateKeyPairDialog):
    keyPairGenerated = pyqtSignal(str, str, int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setup_connections()

    def setup_connections(self):
        self.buttonBox.accepted.connect(self.on_accept)

    def on_accept(self):
        name = self.nameLineEdit.text()
        email = self.emailLineEdit.text()
        key_size = self.comboBox.currentIndex()
        password = self.passLineEdit.text()

        self.keyPairGenerated.emit(name, email, key_size, password)
        self.accept()


class DeleteKeyPairDialog(QDialog, Ui_DeleteKeyPairDialog):
    keyPairChosen = pyqtSignal(str)

    def __init__(self, keys, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setup_connections()

        for key in keys:
            self.comboBox.addItem(f"{key["name"]}, {key["email"]} - {key["key_id"][2:]}", key["key_id"])

    def setup_connections(self):
        self.buttonBox.accepted.connect(self.on_accept)

    def on_accept(self):
        self.keyPairChosen.emit(self.comboBox.currentData())
        self.accept()


class ImportDialog(QDialog, Ui_ImportKeyDialog):
    keyImported = pyqtSignal(str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setup_connections()

    def setup_connections(self):
        self.buttonBox.accepted.connect(self.on_accept)

    def on_accept(self):
        name = self.nameLineEdit.text()
        email = self.emailLineEdit.text()
        passphrase = self.passphraseLineEdit.text()

        self.keyImported.emit(name, email, passphrase)
        self.accept()


class ExportKeyDialog(QDialog, Ui_ExportKeyDialog):
    keyExported = pyqtSignal(str, bool, bool, str)

    def __init__(self, keys, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setup_connections()
        self.keys = keys

        for key in keys:
            self.comboBox.addItem(f"{key["name"]}, {key["email"]} - {key["key_id"][2:]}", key["key_id"])

    def setup_connections(self):
        self.buttonBox.accepted.connect(self.on_accept)

    def on_accept(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        filePath, _ = QFileDialog.getSaveFileName(
            self,
            "Choose the location for the exported key",
            "",
            "PEM Files (*.pem);;All Files(*)",
            options=options
        )

        if filePath is None or filePath == "":
            return

        onlyPublic = self.publicRadioButton.isChecked()
        wholePair = self.pairRadioButton.isChecked()
        self.keyExported.emit(self.comboBox.currentData(), onlyPublic, wholePair, filePath)
        self.accept()


class SendMessageDialog(QDialog, Ui_SendMessageDialog):
    messageCreated = pyqtSignal(str, str, str, str, bool, bool, str)

    def __init__(self, private_keys, public_keys, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setup_connections()
        self.privateComboBox.clear()
        self.publicComboBox.clear()
        self.private_keys = private_keys
        self.public_keys = public_keys

        for key in private_keys:
            self.privateComboBox.addItem(f"{key["name"]}, {key["email"]}", key["key_id"])

        for key in public_keys:
            self.publicComboBox.addItem(f"{key["name"]}, {key["email"]}", key["key_id"])

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
            publicKey = self.publicComboBox.currentData()
        if sign:
            privateKey = self.privateComboBox.currentData()

        with open(filePath, "w") as file:
            file.write(message)

        self.messageCreated.emit(publicKey, privateKey, algorithm, message, compress, convertR64, filePath)
        self.accept()


class ReceiveMessageDialog(QDialog, Ui_ReceiveMessageDialog):
    messageSaved = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setup_connections()

    def setup_connections(self):
        self.buttonBox.accepted.connect(self.on_accept)

    def on_accept(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        filePath, _ = QFileDialog.getSaveFileName(
            self,
            "Choose the decrypted message location",
            "",
            "Message Files (*.msg);;All Files(*)",
            options=options
        )

        if filePath is None or filePath == "":
            return

        message = self.messageText.toPlainText()

        with open(filePath, "w") as file:
            file.write(message)

        self.messageSaved.emit(message)
        self.accept()

# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui/main_window.ui'
#
# Created by: PyQt5 UI code generator 5.15.10
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.generateButton = QtWidgets.QPushButton(self.centralwidget)
        self.generateButton.setGeometry(QtCore.QRect(400, 110, 161, 41))
        self.generateButton.setObjectName("generateButton")
        self.receiveButton = QtWidgets.QPushButton(self.centralwidget)
        self.receiveButton.setGeometry(QtCore.QRect(610, 410, 161, 41))
        self.receiveButton.setObjectName("receiveButton")
        self.sendButton = QtWidgets.QPushButton(self.centralwidget)
        self.sendButton.setGeometry(QtCore.QRect(400, 410, 161, 41))
        self.sendButton.setObjectName("sendButton")
        self.deleteButton = QtWidgets.QPushButton(self.centralwidget)
        self.deleteButton.setGeometry(QtCore.QRect(610, 110, 161, 41))
        self.deleteButton.setObjectName("deleteButton")
        self.importButton = QtWidgets.QPushButton(self.centralwidget)
        self.importButton.setGeometry(QtCore.QRect(400, 260, 161, 41))
        self.importButton.setObjectName("importButton")
        self.exportButton = QtWidgets.QPushButton(self.centralwidget)
        self.exportButton.setGeometry(QtCore.QRect(610, 260, 161, 41))
        self.exportButton.setObjectName("exportButton")
        self.privateTableWidget = QtWidgets.QTableWidget(self.centralwidget)
        self.privateTableWidget.setGeometry(QtCore.QRect(30, 80, 331, 151))
        self.privateTableWidget.setObjectName("privateTableWidget")
        self.privateTableWidget.setColumnCount(4)
        self.privateTableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.privateTableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.privateTableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.privateTableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.privateTableWidget.setHorizontalHeaderItem(3, item)
        self.publicTableWidget = QtWidgets.QTableWidget(self.centralwidget)
        self.publicTableWidget.setGeometry(QtCore.QRect(30, 330, 331, 151))
        self.publicTableWidget.setObjectName("publicTableWidget")
        self.publicTableWidget.setColumnCount(4)
        self.publicTableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.publicTableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.publicTableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.publicTableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.publicTableWidget.setHorizontalHeaderItem(3, item)
        self.privateLabel = QtWidgets.QLabel(self.centralwidget)
        self.privateLabel.setGeometry(QtCore.QRect(140, 30, 91, 21))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setBold(True)
        font.setWeight(75)
        self.privateLabel.setFont(font)
        self.privateLabel.setObjectName("privateLabel")
        self.publicLabel = QtWidgets.QLabel(self.centralwidget)
        self.publicLabel.setGeometry(QtCore.QRect(150, 280, 91, 21))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setBold(True)
        font.setWeight(75)
        self.publicLabel.setFont(font)
        self.publicLabel.setObjectName("publicLabel")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 21))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuKeys = QtWidgets.QMenu(self.menubar)
        self.menuKeys.setObjectName("menuKeys")
        self.menuMessage = QtWidgets.QMenu(self.menubar)
        self.menuMessage.setObjectName("menuMessage")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionSend = QtWidgets.QAction(MainWindow)
        self.actionSend.setObjectName("actionSend")
        self.actionReceive = QtWidgets.QAction(MainWindow)
        self.actionReceive.setObjectName("actionReceive")
        self.actionGenerate = QtWidgets.QAction(MainWindow)
        self.actionGenerate.setObjectName("actionGenerate")
        self.actionDelete = QtWidgets.QAction(MainWindow)
        self.actionDelete.setObjectName("actionDelete")
        self.actionImport = QtWidgets.QAction(MainWindow)
        self.actionImport.setObjectName("actionImport")
        self.actionExport = QtWidgets.QAction(MainWindow)
        self.actionExport.setObjectName("actionExport")
        self.menuFile.addAction(self.actionImport)
        self.menuFile.addAction(self.actionExport)
        self.menuKeys.addAction(self.actionGenerate)
        self.menuKeys.addAction(self.actionDelete)
        self.menuMessage.addAction(self.actionSend)
        self.menuMessage.addAction(self.actionReceive)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuKeys.menuAction())
        self.menubar.addAction(self.menuMessage.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "PGP"))
        self.generateButton.setText(_translate("MainWindow", "Generate Key Pair"))
        self.receiveButton.setText(_translate("MainWindow", "Receive Message"))
        self.sendButton.setText(_translate("MainWindow", "Send Message"))
        self.deleteButton.setText(_translate("MainWindow", "Delete Key Pair"))
        self.importButton.setText(_translate("MainWindow", "Import"))
        self.exportButton.setText(_translate("MainWindow", "Export"))
        item = self.privateTableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Name"))
        item = self.privateTableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Email"))
        item = self.privateTableWidget.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Key Size"))
        item = self.privateTableWidget.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Key ID"))
        item = self.publicTableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Name"))
        item = self.publicTableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Email"))
        item = self.publicTableWidget.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Key Size"))
        item = self.publicTableWidget.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Key ID"))
        self.privateLabel.setText(_translate("MainWindow", "Private Keyring"))
        self.publicLabel.setText(_translate("MainWindow", "Public Keyring"))
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuKeys.setTitle(_translate("MainWindow", "Keys"))
        self.menuMessage.setTitle(_translate("MainWindow", "Message"))
        self.actionSend.setText(_translate("MainWindow", "Send"))
        self.actionSend.setShortcut(_translate("MainWindow", "Ctrl+S"))
        self.actionReceive.setText(_translate("MainWindow", "Receive"))
        self.actionReceive.setShortcut(_translate("MainWindow", "Ctrl+R"))
        self.actionGenerate.setText(_translate("MainWindow", "Generate"))
        self.actionGenerate.setShortcut(_translate("MainWindow", "Ctrl+G"))
        self.actionDelete.setText(_translate("MainWindow", "Delete"))
        self.actionDelete.setShortcut(_translate("MainWindow", "Ctrl+D"))
        self.actionImport.setText(_translate("MainWindow", "Import"))
        self.actionImport.setShortcut(_translate("MainWindow", "Ctrl+I"))
        self.actionExport.setText(_translate("MainWindow", "Export"))
        self.actionExport.setShortcut(_translate("MainWindow", "Ctrl+E"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
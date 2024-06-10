from sys import argv, exit
from PyQt5.QtWidgets import QApplication
from gui import PGPApp


if __name__ == "__main__":
    app = QApplication(argv)
    win = PGPApp()
    win.show()
    exit(app.exec_())

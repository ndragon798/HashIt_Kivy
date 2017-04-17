import kivy
from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.gridlayout import GridLayout
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.popup import Popup
import hashlib
import webbrowser
import json
import ssl
import requests
import urllib

API_KEY = '96de2701aaf40a46f2b358255625c077ce823a71c52645f7d0385befe96e8855'
#vt = VirusTotalPublicApi(API_KEY)


class MyFileChooser(FileChooserListView):

    def on_submit(*args):
        print(args[1][0])
        global fp
        global fps
        fp = args[1][0]
        fps = args[1][0]
        print(fp)
        popup.dismiss()


class MainScreen(BoxLayout):

    def scan(self, instance):
        print("FPS: ", fps)
        params = {'apikey': API_KEY}
        files = {'file': (fps, open(fps, 'rb'))}
        response = requests.post(
            'https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        scanresults = response.json()
        try:
            dlink = str(scanresults["permalink"])
        except Exception as e:
            print(e)
            dlink = 'http://www.nathaneaston.com/'
        print(dlink)
        webbrowser.open(dlink)

    def genhash(self, instance):
        try:
            print(fp)
            print(self.md5(fp))
            print(self.sha1(fp))
            print(self.sha256(fp))
            self.lmd5.text = 'MD5: '+self.md5(fp)
            self.lsha1.text = 'SHA1: '+self.sha1(fp)
            self.lsha256.text = 'SHA256: '+self.sha256(fp)
            self.lsha256.font_size = (self.width/50)
            self.lsha1.font_size = (self.width/50)
            self.lmd5.font_size = (self.width/50)
            self.add_widget(self.btnupload)

        except:
            print('fp not defined')

    def md5(self, fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def sha1(self, fname):
        hash_sha1 = hashlib.sha1()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha1.update(chunk)
        return hash_sha1.hexdigest()

    def sha256(self, fname):
        hash_sha256 = hashlib.sha256()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def filebtn(self, instance):
        # print("test")
        global popup
        popup = Popup(title='Select File',
                      content=MyFileChooser(),
                      size_hint=(None, None), size=self.size)
        popup.open()

        try:
            self.add_widget(self.btnhash)
        except:
            print("Button already added")

    def __init__(self, **kwargs):
        super(MainScreen, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.btnfile = Button(text='Open File')
        self.btnfile.bind(on_press=self.filebtn)
        self.btnhash = Button(text='Generate Hashes')
        self.btnhash.bind(on_press=self.genhash)
        self.btnupload = Button(text='Upload File')
        self.btnupload.bind(on_press=self.scan)
        # self.
        self.lmd5 = Label(text='MD5: ')
        self.lsha1 = Label(text='SHA1: ')
        self.lsha256 = Label(text='SHA256: ')
        self.add_widget(self.btnfile)
        self.add_widget(self.lmd5)
        self.add_widget(self.lsha1)
        self.add_widget(self.lsha256)


class MyApp(App):

    def build(self):
        return MainScreen()


if __name__ == '__main__':
    MyApp().run()

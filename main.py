
from tkinter import *   #To create the GUI
from string import *    #To get all the characters
from random import randint  #To generate random numbers
from time import sleep
import pyperclip    #To copy password
import hashlib  #To hash the keyword you associated with the password
import os   #To check if you already have the passwords in file in the current directory (first launch or not)
import smtplib  #To send the email with the verification code
import sys  #To stop the program if it can't send the verification code

code = str(randint(100000, 999999)) #Generate the verification code


def main(): #Main function wich start after the verification (Go to connect function)

    files = [f for f in os.listdir(".") if os.path.isfile(f)]   #List all files in the current directory

    if not "passwords" in files:    #If there isn't a passwords file in the current directory
        with open("passwords", "w") as f:   #Create one
            f.write("Beta 1.0\n")  #Write "Beta 1.0" in and save it

    s = ascii_lowercase+ascii_uppercase+digits+punctuation  #Keep all characters in a string

    def encrypt(keyword, password): #Function to encrypt password
        inted = [(ord(keyword[0])**2)%255]
        for x in range(1, len(keyword)):
            inted.append((((ord(keyword[x])**2)%255)*inted[-1]))

        out = "".join([hex(ord(password[x])*inted[x%len(inted)]) for x in range(len(password))])
        return out

    def decrypt(keyword, encrypted):    #Function to decrypt password
        inted = [(ord(keyword[0])**2)%255]
        for x in range(1, len(keyword)):
            inted.append((((ord(keyword[x])**2)%255)*inted[-1]))

        cool = encrypted.split("0x")[1:]
        out = [chr(int(cool[x], 16)//inted[x%len(inted)]) for x in range(len(cool))]
        return "".join(out)

    def gen():  #Function to generate a password from a keyword
        password = "".join([s[randint(0, len(s)-1)] for x in range(16)])    #Create the password with random characters in s
        site = generatorEntry.get() #Get the keyword in generatorEntry
        generatorEntry.delete(0, "end") #Clear generatorEntry
        out = hashlib.sha256(bytes(site.encode())).hexdigest()+" : "+"\n"+encrypt(site, password)+"\n"  #The output to write in passwords is the hash of the keyword+" : "+"\n"+ the encrypted password
        with open("passwords", "r") as f:   #Open passwords to read
            if not hashlib.sha256(bytes(site.encode())).hexdigest() in f.read():    #If the keyword isn't in passwords (No password registred with this keyword)
                with open("passwords","a") as a:    #Open passwords to append
                    a.write(out)    #Append the output
                    #Show "Password registered !" in genFrame for 2000ms
                    writed = Label(genFrame, text="Password registered !", font=("Neufreit", 18), bg="#3a5fcd", fg="#31db1a")
                    writed.pack(pady=10, fill=X)
                    writed.after(2000, lambda: writed.destroy())
            else:   #If the keyword is already in passwords, show "Already in passwords" in genFrame for 2000ms
                already = Label(genFrame, text="ALREADY IN PASSWORDS !", font=("Neufreit", 18), bg="#3a5fcd", fg="#941910")
                already.pack(pady=10, fill=X)
                already.after(2000, lambda: already.destroy())

    def get():  #Function to get a password from a keyword
        with open("passwords", "r") as f:   #Open passwords to read
            text = f.readlines()    #Keep all the files (split by lines) in a string
        if hashlib.sha256(bytes(getEntry.get().encode())).hexdigest()+" : \n" in text:  #If the keyword is in passwords
            pos = text.index(hashlib.sha256(bytes(getEntry.get().encode())).hexdigest()+" : \n")+1  #Find his position
            encrypted = text[pos]   #Keep the encrypted password
            password = decrypt(getEntry.get(), encrypted)   #Decrypt it
            pyperclip.copy(password)    #Copy it
            getEntry.delete(0, "end")   #Clear the entry
            
            #Show "copied !" in getFrame for 2000ms
            copied = Label(getFrame, text="COPIED !", font=("Neufreit", 18), bg="#3a5fcd", fg="#31db1a")
            copied.pack(pady=10, fill=X)
            copied.after(2000, lambda: copied.destroy())

        else:   #IF keyword isn't in passwords
            getEntry.delete(0, "end")   #Clear entry
            #Show "Not in passwords !" in getFrame for 2000ms
            notIn = Label(getFrame, text="NOT IN PASSWORDS !", font=("Neufreit", 18), bg="#3a5fcd", fg="#941910")
            notIn.pack(pady=10, fill=X)
            notIn.after(2000, lambda: notIn.destroy())
    
    def deleteEntry(entry): #Function to clear the entry after first click in
        entry.delete(0, "end")  #Clear the entry
        entry.config(show="*", fg="black")  #Change show parameters to "*" wich means "*" will replace every characters

    def changeshow(entry, button):  #Function to switch show from normal("") to hide("*") and vice versa
        if entry.cget("show")=="*": #If show=="*": switch to show="" and change <entry>HideButton icon
            entry.config(show="")
            button.config(image=hideicon)
        else:   #Else switch to show="*" and change <entry>HideButton icon
            entry.config(show="*")
            button.config(image=showicon)

    screen.config(background="#3a5fcd") #Change screen background to blue
    genFrame = Frame(screen, bg="#3a5fcd")  #Create a frame to generate passwords
    getFrame = Frame(screen, bg="#3a5fcd")  #Create a frame to get passwords

    #Pack them
    genFrame.pack(expand=YES)
    getFrame.pack(expand=YES)   
    
    #Generator Frame
    Label(genFrame, text="PASSWORD GENERATOR", font=("Neufreit", 20), bg="#3a5fcd", fg="white").pack(pady=10, fill=X)   #Write that this is the generator Frame

    genEntryFrame = Frame(genFrame, bg="#3a5fcd")   #Create a specific frame for the entry and the show button to put them one next to the other
    genEntryFrame.pack(pady=10, expand=YES, fill=X)
    
    showicon = PhotoImage(file="show.png")  #Load show.png in a var
    hideicon = PhotoImage(file="hide.png")  #Load hide.png in a var
    generatorHideButton = Button(genEntryFrame, image=showicon, bg="white", command=lambda: changeshow(generatorEntry, generatorHideButton))    #Create the generatorHideButton, specify the image
    generatorHideButton.pack(side=RIGHT)    #Put it on the right of the frame

    generatorName = StringVar() #String to keep the generatorEntry input

    generatorEntry = Entry(genEntryFrame, textvariable=generatorName, validate="focusin", fg="grey",validatecommand= lambda: deleteEntry(generatorEntry)) #Create the generatorEntry, validate="focusin" and validatecommand= lambda: deleteEntry(generatorEntry) means that when you will click in the entry to write it will call deleteEntry to clear generatorEntry
    generatorEntry.pack(pady=5,padx=10, fill=X) #Set pady and padx to center it
    generatorEntry.insert(0, "keyword") #Put "keyword" in because it's more professional
   
    generatorButton = Button(genFrame, text="GENERATE", command=gen, font=("Neufreit", 16), bg="white", fg="#3a5fcd")   #Button to validate the input
    generatorButton.pack(pady=10, fill=X)

    #Get Frame  (same thing than Generator Frame)
    Label(getFrame, text="   GET PASSWORD   ", font=("Neufreit", 20), bg="#3a5fcd", fg="white").pack(pady=10, fill=X)
    
    getEntryFrame = Frame(getFrame, bg="#3a5fcd")
    getEntryFrame.pack(pady=10, expand=YES, fill=X)

    getHideButton = Button(getEntryFrame, image=showicon, bg="white", command=lambda: changeshow(getEntry, getHideButton))
    getHideButton.pack(side=RIGHT)

    getName = StringVar()

    getEntry = Entry(getEntryFrame, textvariable=getName, validate="focusin", fg="grey",validatecommand= lambda: deleteEntry(getEntry))
    getEntry.pack(pady=5, padx=10, fill=X)
    getEntry.insert(0, "keyword")
    
    getButton = Button(getFrame, text="  COPY  ", command=get, font=("Neufreit", 16), bg="white", fg="#3a5fcd")
    getButton.pack(pady=10, fill=X)

    screen.mainloop()

def connect(code):  #Check if its really you behind your computer (call after pressing connect Button created below)

    TO = ''    #Your adresse email
    SUBJECT = 'Verification'    #The subject of the mail
    TEXT = code #The verification code is the mail

    #Gmail Sign In
    gmail_sender = ''   #Create an gmail address and allow low security apps access to send you the verification code
    gmail_passwd = ''   #The password of this email adress

    #Connection to the sender mail account
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    server.login(gmail_sender, gmail_passwd)
    
    #Construct the mail
    BODY = '\r\n'.join(['To: %s' % TO,
                        'From: %s' % gmail_sender,
                        'Subject: %s' % SUBJECT,
                        '', TEXT])
    
    #Try to send the mail
    try:    #If it works
        server.sendmail(gmail_sender, [TO], BODY)
        print ('email sent')    #Control Print
        
        #Show that the verification has been sent to your reception address for 2000ms
        emailsent = Label(screen, text="EMAIL SENT !", font=("Neufreit", 18), bg="black", fg="#31db1a")
        emailsent.pack(pady=10, fill=X)
        emailsent.after(2000, lambda: emailsent.destroy())

        sended = True   #Keep the fact that the email has been sent
    
    except: #If it doesn't
        print ('error sending mail')    #Control Print
        sended = False  #Keep the fact that email hasn't been sent
    
    server.quit()   #Disconnect sender address account
    
    if sended:  #If the verification code has been sent:
        connectButton.destroy() #Destroy the connect Button
        
        connectFrame = Frame(screen, bg="black")    #Create a connection Frame in the screen with a black background
        connectFrame.pack(expand=YES)   #The frame takes all the screen
        
        Label(connectFrame, text="VERIFICATION CODE:", font=("Neufreit", 32), bg="black", fg="blue").pack(pady=10)  #Write "VERIFICATION CODE:" in the connectFrame above the code entry. pack() is necessary to display the label in the frame and pady means the all the elements above and below will be spaced by 10

        connectName = StringVar()   #Necessary to keep the input of the entry
        connectEntry = Entry(connectFrame, textvariable=connectName)    #Create the entry in connectFrame and specify the input will be kept in connectName
        connectEntry.pack(pady=10, fill=X)  #fill=X means the entry will takes every place it can on right and left
        
        def delfg(entry):
            entry.delete(0, "end")
            entry.config(fg="black")

        def checkingverif(code, entry):    #Check if input is the same as the code (call by the button below)
            global tries
            tries-=1
            if code==connectEntry.get():    #If it is
                connectFrame.destroy()  #Destroy the connectFrame
                main()  #Start the main function
            elif tries:
                entry.delete(0, "end")
                entry.config(fg="red")
                entry.insert(0, str(tries)+" tries left !")
                entry.after(1000, lambda: delfg(entry))
            else:
                sys.exit()

        Button(connectFrame, text="ENTER", command= lambda: checkingverif(code, connectEntry), font=("Neufreit", 20), bg="white", fg="blue").pack(pady=10)    #Button to validate the input
    else:   #If the verification hasn't been sent:
        sys.exit()  #Exit the program

screen = Tk()   #Create the screen
screen.title("")    #Set title to screen to ""
screen.geometry("720x400")  #Set the screen size
screen.config(background="black")   #Set the screen background

connectButton = Button(screen, text="CONNECT", command= lambda: connect(code), font=("Neufreit", 32), bg="white", fg="blue")    #Create connect Button wich will call connect(code) if it's pressed
connectButton.pack(expand=YES)  #Specify the button takes all the screen
tries = 3
screen.mainloop()   #Loop the screen necessary to display the screen

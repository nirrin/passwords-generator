#!/usr/bin/env python

import os
from xkcdpass import xkcd_password as xp
from zxcvbn import zxcvbn
from zxcvbn.matching import add_frequency_lists
from flask import Flask, render_template, send_from_directory, request, jsonify, Response

class Passwords:
	def __init__(self, wordfile=None, min_length=5, max_length=9, valid_chars="."):
		self.wordfile = xp.locate_wordfile(wordfile)
		self.words = xp.generate_wordlist(wordfile=wordfile, min_length=min_length, max_length=max_length, valid_chars=".")
		add_frequency_lists({ "words": self.words})

	def generate(self, numwords=6, acrostic=False, delimiter=" "):
		return xp.generate_xkcdpassword(wordlist=self.words, numwords=numwords, interactive=False, acrostic=acrostic, delimiter=delimiter)

	def strength_score(self, score):
		return {
  			0 : lambda score: "too guessable: risky password",
  			1 : lambda score: "very guessable: protection from throttled online attacks",
  			2 : lambda score: "somewhat guessable: protection from unthrottled online attacks",
  			3 : lambda score: "safely unguessable: moderate protection from offline slow-hash scenario",
  			4 : lambda score: "very unguessable: strong protection from offline slow-hash scenario"
			}[score](score)	

	def strength(self, password, user_inputs=[]):		
		strength = zxcvbn(password, user_inputs=user_inputs)
		del strength ["sequence"]
		del strength["crack_times_seconds"]
		del strength["calc_time"]
		del strength["guesses_log10"]
		del strength["password"]
		strength["strength"] = self.strength_score(strength["score"])		
		return strength

app = Flask(__name__)
passwords = Passwords()

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static"), "favicon.ico", mimetype="image/vnd.microsoft.icon")	

@app.route("/", methods = ["GET"])
def root():
	return app.send_static_file("password.html")	

@app.route("/generate", methods = ["POST"])
def generate():	
	acrostic = request.form["acrostic"]			
	password = passwords.generate(numwords=int(request.form["numwords"]), acrostic=acrostic if acrostic != "" else False, delimiter=request.form["delimiter"])		
	return jsonify(password=password, strength=passwords.strength(password))

@app.route("/check", methods = ["POST"])
def check():			
	password = request.form["password"]		
	return jsonify(passwords.strength(password))

if __name__ == "__main__":
	context = ("cert.pem", "key.pem")	
	app.run(host='0.0.0.0', port=5000, ssl_context=context, threaded=True, debug=True)

		
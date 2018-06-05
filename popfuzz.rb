#!/usr/bin/env ruby
######################################################
## Product: POPFuzz v0.9
## Description: POP3 Client fuzzer
## Filename: popfuzz.rb (Must be executable)
## Author: Resheph
## Ruby 1.9.3 +
## Started: 2015
## Usage: ./popfuzz.rb &
## OS: Any that supports Ruby
######################################################
# Purpose: Fuzzing client POP3 software by giving overly long responses to client commands etc.
# Must run as root to be able to listen on port 1023 or below.
# RFC 1081 POPv3 - obsolete
# Software is free for all to use.
# Known Bugs: Lots
# - Does not handle unknown commands at all.
# - Errorhandling missing but not really needed.
# - Released files should have no file extension.

## Required modules
require 'socket'

## Constants
PORT = 110										# Port to listen on
BANNER = "+OK POPFuzz v0.9 Server Ready"
LISTEN_IP = "0.0.0.0"							# Listen on INADDR_ANY
USERNAME ="postmaster"							# Account for the client to use
PASSWORD = "Qwert"								# Password for the client to use
DOMAIN = "@example.com"							# Domain to be presented in tne static email.

# Freeze constants. (SHould be done directly on the receiver, but it seems to not work in older versions of Ruby)
PORT.freeze
BANNER.freeze
LISTEN_IP.freeze
USERNAME.freeze
PASSWORD.freeze
DOMAIN.freeze

## Globals
$num_messages = 1								# Number of messagens the server holds. Only one static is currently in place.

# *** Message 1 beginning ***
$msg1 = <<-END_OF_STRING
Return-Path: <no-reply@example.com>
Delivered-To: #{USERNAME}#{DOMAIN}
Received: from localhost (unknown [10.1.3.25])
	by harmony.local (Postfix) with ESMTP id 2CC88637E2
	for <#{USERNAME}#{DOMAIN}>; Wed, 13 May 2015 10:02:52 +0200 (CEST)
To: #{USERNAME}#{DOMAIN}
Subject: Hello
Message-ID: <0c4488f96a9385eed5de73fdfc366445@example.com>
Date: Wed, 13 May 2015 04:17:57 +0000
From: "Administrator" <no-reply@example.com>
Reply-To: no-reply@example.com
MIME-Version: 1.0
Content-Type: multipart/alternative; charset="UTF-8"; boundary="b1_5ecf0dd9b89ef5875fcc3e3ead24e962"
Content-Transfer-Encoding: 8bit
Content-Type: text/plain; format=flowed; charset="UTF-8"
Content-Transfer-Encoding: 8bit

--b1_5ecf0dd9b89ef5875fcc3e3ead24e962
Content-Type: text/plain; format=flowed; charset="UTF-8"
Content-Transfer-Encoding: 8bit

Hey

The secret word is 07e905c62c9590046b561abc0c295126.

--b1_5ecf0dd9b89ef5875fcc3e3ead24e962
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 8bit

<html><head></head><body>
Hey<br />
The secret word is 07e905c62c9590046b561abc0c295126.
</body></html>


--b1_5ecf0dd9b89ef5875fcc3e3ead24e962--
END_OF_STRING
# *** Message 1 ending ***


## Main
socket = TCPServer.new(LISTEN_IP, PORT)			# Create a server socket (for listening)

# Main loop
loop do											# Keep listening
	Thread.start(socket.accept) do |client|		# Handle accept() and spawn a thread for each client connection.
		client.puts BANNER						# Send banner to client according to RFC
		_state = "AUTHORIZATION"				# Keep track of POP3 states
		_username = ""							# This is to verify that the USER is set before accepting PASS		

		# AUTHORIZATION state
		while _state == "AUTHORIZATION"
			_message = client.gets				# Read command from client
			_command = ""						# Initialize command variable to ""
			_argument = ""						# Initialize command argument to ""
			_command, _argument = _message.chomp.split(/ /)		# Remove CR and LF if present and split the message into a command and an argument variable.

			# USER
			if _command == "USER" and _state != "AUTHORIZATION"									# USER command while not i AUTHORIZATION state. This should not happen.
				client.puts "-ERR You should not do this now"
			elsif _command == "USER" and !_argument and _state == "AUTHORIZATION"			# USER was not followed by a username. State is correct.
				client.puts "-ERR missing username"
			elsif _command == "USER" and _argument == USERNAME and _state == "AUTHORIZATION"	# USER command matches an account. State is correct
				_username = _argument
				client.puts "+OK #{_username} is hanging out here"
			elsif _command == "USER" and _argument != USERNAME and _state == "AUTHORIZATION"	# User command did not match requested account. State is correct.
				client.puts "-ERR #{_argument} does not hang out here"
			end

			# PASS
			if _command == "PASS" and _state != "AUTHORIZATION"									# PASS command given while not in AUTHORIZATION state. This should not happen.
				client.puts "-ERR You should not do this now"
			elsif _command == "PASS" and _username != USERNAME and _state == "AUTHORIZATION"	# PASS called before USER. State is correct.
				client.puts "-ERR You should do USER first"
			elsif _command == "PASS" and !_argument and _state == "AUTHORIZATION"				# PASS was not followed by a password. State is correct.
				client.puts "-ERR Passowrd missing"
			elsif _command == "PASS" and _argument != PASSWORD and _username == USERNAME and _state == "AUTHORIZATION"	# Password was not correct. State is correct.
				client.puts "-ERR Passowrd incorrect for that user"
			elsif _command =="PASS" and _argument == PASSWORD and _state == "AUTHORIZATION"		# PASS matches. State is correct
				client.puts "+OK #{_username} is now authorized"
				_state = "TRANSACTION"													# Authorization complete. Change state according to RFC. This will end current loop that handle the AUTHORIZATION state.
			end

			# QUIT
			if _command == "QUIT"
				client.puts "+OK leaving"
				_state = "ENDING"
			end

			# AUTH FIXME: Not implemented
			if _command == "AUTH"
				client.puts "-ERR What are you doing?"
			end

			# CAPA FIXME: Not implemented
			if _command == "CAPA"
				client.puts "-ERR What are you doint?"
			end
		end

		# TRANSACTION State
		while _state == "TRANSACTION"
			_message = client.gets									# Read command from client
			_command, _argument = _message.chomp.split(/ /)			# Remove newlines ans split the message using space as a seperator

			# STAT
			if _command == "STAT" and _state != "TRANSACTION"		# STAT given in wrong state. This should not happen.
				client.puts "-ERR You should not do that now"
			elsif _command == "STAT" and _state == "TRANSACTION"	# STAT is given. State is correct.
				client.puts "+OK #{$num_messages} #{$msg1.size}"
			end

			# LIST
			if _command == "LIST" and _state != "TRANSACTION"		# LIST is given in wrong state. This should not happen.
				client.puts "-ERR You should not do this now"
			elsif _command == "LIST" and !_argument and _state == "TRANSACTION"		# LIST is given with no arguments. This is OK.
				client.puts "+OK #{$num_messages} messages (#{$msg1.size} octets)"	# This should not be done this way. Make sure to calculate size of all messages in total if more than one exists.
				client.puts "1 #{$msg1.size}"
				client.puts "."
			elsif _command == "LIST" and _argument == "1" and _state == "TRANSACTION"
				client.puts "+OK #{_argument} #{$msg1.size}"
			end

			# RETR
			if _command == "RETR" and _state != "TRANSACTION"
				client.puts "-ERR You should not do this now"
			elsif _command == "RETR" and !_argument and _state == "TRANSACTION"
				client.puts "-ERR Message number missing"
			elsif _command == "RETR" and _argument == "1" and _state == "TRANSACTION"
				client.puts "+OK #{$msg1.size} octets"
				client.puts $msg1
				client.puts "."
			end

			# DELE (This does not actually delete the message, but returns a appropriate reply)
			if _command == "DELE" and _state != "TRANSACTION"
				client.puts "-ERR You should not do this now"
			elsif _command == "DELE" and !_argument and _state == "TRANSACTION"
				client.puts "-ERR no such message"
			elsif _command == "DELE" and _argument == "1" and _state == "TRANSACTION"
				client.puts "+OK message 1 deleted"
			end

			# NOOP
			if _command == "NOOP" and _state != "TRANSACTION"
				client.puts "-ERR You should not do this now"
			elsif _command == "NOOP" and _state == "TRANSACTION"
				client.puts "+OK"
			end

			# LAST FIXME: Not implemented
			if _command == "LAST" and _state != "TRANSACTION"
				client.puts "-ERR You should not do that now"
			elsif _command == "LAST" and _state == "TRANSACTION"
				client.puts "+OK 1"
			end

			# RSET
			if _command == "RSET" and _state != "TRANSACTION"
				client.puts "-ERR You should not do this now"
			elsif _command == "RSET" and _state == "TRANSACTION"
				client.puts "+OK maildrop has #{$num_messages} messages (#{$msg1.size} octets)"
			end

			# UIDL FIXME: Not implemented
			if _command == "UIDL"
				client.puts "-ERR not supported"
			end

			# XTND FIXME: Not implemented
			if _command == "XTND"
				client.puts "-ERR not supported"
			end

			# TOP FIXME: Not implemented
			if _command == "TOP"
				client.puts "-ERR not supported"
			end

			# QUIT
			if _command == "QUIT"
				client.puts "+OK leaving"
				_state = "ENDING"
			end
		end		# while

		# ENDING state (and all other states not handled - if any)
		client.close		# Close the client socket
	end		# End the thread that handle the current client
end 	# Mail loop end

socket.close				# Close the server socket. This should never happen. Use CTRL+C to stop the server.



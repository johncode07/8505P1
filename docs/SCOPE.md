# Attacker Design

- The commander presents a menu that must include at least the following:
- Connect to the victim (menu or command line args)
- Disconnect from the victim
- Uninstall from the victim
- Start the keylogger on the victim
- Stop the keylogger on the victim
- Transfer the key log file from the victim (can be automatic or via the menu)
- Transfer a file to the victim
- Transfer a file from the victim
- Watch a file on the victim
- Watch a directory on the victim
- Run a program on the victim
- The commander must port-knock on the victim to initiate a session.
- Once a session is initiated, it continues until the commander selects the Disconnect
menu item.
- All communication for the session must be done via covert channels (you cannot use the
urgent pointer or UDP source port).
- When a program is run on the victim, the output appears on the commander.
- To alter the /etc/shadow file, use the useradd or passwd commands.

# Victim Design

- The victim program must implement all of the features listed in the commander.
- The victim program must try to conceal its name using the algorithm described in the
notes
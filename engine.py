from webex_bot.models.command import Command
from webex_bot.models.response import Response
import logging
import requests
import json
from alert_card import create_card_content
import config  as conf
from crayons import *

log = logging.getLogger(__name__)

class cmd(Command):
    def __init__(self):
        super().__init__(
            command_keyword="temp",
            help_message="Ask Service to XDR",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        # message will contain the word given after temp : ex paris is we type temp paris into the bot room
        r = requests.get("https://prevision-meteo.ch/services/json/paris")
        json_raw = r.content
        parsed_json = json.loads(json_raw)
        #print(json.dumps(parsed_json, indent = 4, sort_keys=True))
        #print(parsed_json)
        temp_act = (parsed_json['current_condition']['tmp'])
        print('current temparture in Paris : ',temp_act)    
        return f"current temparture in Paris is : {temp_act} Degrees"
        
class cmd2(Command):
    def __init__(self):
        super().__init__(
            command_keyword="alert",
            help_message="Ask Service to XDR",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        alert_message="Suspicious Activity Detected"
        cards_content=create_card_content(alert_message)
        response = Response()
        response.text = "XDR Alert !"
        # Attachments being sent to user
        response.attachments = cards_content[0]
        return response
 
class cmd3(Command):
    def __init__(self):
        super().__init__(
            command_keyword="targets",
            help_message="get targets",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        targets=attachment_actions.inputs['targets']
        return f"Selected Targets to isolate are : {targets} "
              
class cmd4(Command):
    def __init__(self):
        super().__init__(
            command_keyword="/check-ngrok",
            help_message="check if ngrok process run on host",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        #observables=attachment_actions.inputs['observables']
        message=message.strip()
        print()
        print('host on which to check : *',message)
        print()

        headers = {'Content-Type':'application/json', 'Accept':'application/json'}
        post_data = { "IP": message }
        response = requests.post(conf.XDR_WEBHOOK_FOR_INVESTIGATION, headers=headers,json=post_data)
        print('Webhook API call to XDR http result :\n',response)           
        return f"OK XDR workflow triggered for host : {message}...Waiting for reply... "
        
class cmd5(Command):
    def __init__(self):
        super().__init__(
            command_keyword="observables",
            help_message="observables to block had been received from Webex formular",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        observables=attachment_actions.inputs['observables']
        print('observables received from formular : ',yellow(observables,bold=True))
        observables=observables.split(',') 
        for observable in observables:
            print('Observable to block : ',cyan(observable,bold=True))
            pid_to_kill=observable.split('PID :')[1]
            pid_to_kill=pid_to_kill.split(' )(')[0]
            pid_to_kill=pid_to_kill.strip()
            hostname=observable.split(')( ')[1].replace(' )','')
            hostname=hostname.strip()
            print()
            print('PID to kill :',pid_to_kill)
            print()
            print()
            print('In hostname :',hostname)
            print()
            headers = {'Content-Type':'application/json', 'Accept':'application/json'}
            post_data = { "Hostname": hostname, "Pid": pid_to_kill }
            print()
            print('post_data :\n',post_data)
            print()
            response = requests.post(conf.XDR_WEBHOOK_FOR_KILLING_PROCESS, headers=headers,json=post_data)
            print('Webhook API call to XDR http result :\n',response)           
        return f"Asking to XDR to kill process : {observables} "

        
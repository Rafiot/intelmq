# -*- coding: utf-8 -*-
import sys

import rt
from intelmq.lib.bot import Bot
import requests
from string import Template


class RTOutputBot(Bot):

    def is_up(self, ua):
        r = requests.get(self.url, headers={'User-Agent': ua})
        if len(r.text) > 5000:
            return True
        return False

    def make_mail_template(self, event):
        content = []

        content.append(event.get("source.url"))
        if event.get("source.google_safe_browsing"):
            content.append('\tKnown as malicious on Google Safe Browsing: {}'.format(
                event.get("source.google_safe_browsing")))

        if event.get("source.phishtank"):
            content.append('\tknown as malicious on phishtank')

        if event.get("virustotal.positive"):
            if event.get("virustotal.positive") > 0:
                content.append('\tvirustotal positive detections: {} out of {}\n\tVirus total details: {}'.format(
                    event.get("virustotal.positive"), event.get("virustotal.total"), event.get("virustotal.url")))

        if event.get("source.ip"):
            content.append('\t{}'.format(event.get("source.ip")))
        if event.get("source.reverse_dns"):
            content.append('\t\t(ptr: {}) is announced by {} ({}).'.format(
                event.get("source.reverse_dns"), event.get("source.as_name"),
                event.get("source.asn")))

        return '\n\n '.join(content)

    def process(self):
        RT = rt.Rt(self.parameters.uri, self.parameters.user,
                   self.parameters.password, verify_cert=False)
        try:
            RT.login()
        except:
            pass
        if not RT.login():
            raise ValueError('login failed.')

        event = self.receive_message()
        self.url = event.get("source.url")
        if not self.is_up(self.parameters.useragent):
            self.acknowledge_message()
            return

        if not event.contains("source.abuse_contact"):
            self.logger.warning("Unable to find contact information for {}, uwhois down?".format(self.url))
            self.acknowledge_message()
            return

        emails = event.get("source.abuse_contact")
        asn_descr = event.get("source.as_name")
        master_ticket = event.get("rtir_id")

        d = {'details': self.make_mail_template(event)}
        with open(self.parameters.template, 'r') as f:
            subject = '{} ({})'.format(f.readline().rstrip(), asn_descr)
            templatecontent = Template(f.read())
            body = templatecontent.substitute(d)
        content = {'Queue': self.parameters.RTQueue, 'requestor': emails, 'subject': subject, 'text': body}
        ticket_id = RT.create_ticket(**content)
        if master_ticket:
            RT.edit_link(ticket_id, 'MemberOf', master_ticket)
        self.acknowledge_message()

if __name__ == "__main__":
    bot = RTOutputBot(sys.argv[1])
    bot.start()

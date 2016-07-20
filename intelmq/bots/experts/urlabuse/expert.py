#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from intelmq.lib.bot import Bot
import pyurlabuse
from intelmq.lib.message import Event
import time


class URLAbuseExpertBot(Bot):

    def url_to_events(self, src_event, url, info):
        global_event = Event(src_event)
        global_event.update('source.url', url)
        all_emails = []
        if info.get('whois'):
            all_emails = info.get('whois')
            contacts = list(set(info.get('whois')))
            global_event.add('source.abuse_contact', ','.join(contacts))
        if info.get('gsb'):
            global_event.add('source.google_safe_browsing', info.get('gsb'))
        if info.get('phishtank'):
            global_event.add('source.phishtank', True)
        if info.get('vt') and len(info.get('vt')) == 4:
            global_event.add('virustotal.url', info.get('vt')[1])
            global_event.add('virustotal.positive', info.get('vt')[2])
            global_event.add('virustotal.total', info.get('vt')[3])

        if info.get('dns'):
            ipv4, ipv6 = info.get('dns')
            if ipv4:
                for ip in ipv4:
                    e = Event(global_event)
                    e.add('source.ip', ip)
                    data = info[ip]
                    if data.get('whois'):
                        all_emails += data.get('whois')
                        contacts = list(set(all_emails))
                        if e.get('source.abuse_contact'):
                            e.update('source.abuse_contact', ','.join(contacts))
                        else:
                            e.add('source.abuse_contact', ','.join(contacts))
                    if data.get('bgp'):
                        ptr, asn_descr, asn = data.get('bgp')[:3]
                        e.add('source.reverse_dns', ptr)
                        e.add('source.as_name', asn_descr)
                        e.add('source.asn', asn)
                    self.send_message(e)
            if ipv6:
                for ip in ipv6:
                    e = Event(global_event)
                    e.update('source.url', url)
                    e.add('source.ip', ip)
                    self.send_message(e)
        else:
            self.send_message(global_event)

    def process(self):
        abuse = pyurlabuse.PyURLAbuse(self.parameters.url)
        event = self.receive_message()
        if not event.contains("source.url"):
            self.acknowledge_message()
            return
        url = event.get("source.url")
        msg, data = abuse.run_query(url)
        if msg.get('status') == 'new':
            # Give some time for the queries to finish.
            time.sleep(15)
            msg, data = abuse.run_query(url)
        for entry in data:
            for url, info in entry.items():
                self.url_to_events(event, url, info)
        self.acknowledge_message()


if __name__ == "__main__":
    bot = URLAbuseExpertBot(sys.argv[1])
    bot.start()

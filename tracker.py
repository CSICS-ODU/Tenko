import random
import string
import requests
# import asyncio
# import aiohttp
import _thread
import threading

import pdb, traceback, time

class scoreClass():
    """docstring for scores"""
    def __init__(self, timestamp, n, d=1, timestep=10000, historyEpoch=100000, initial_key=0):
        if d == 1:
            assert 0 <= n <= 1, "n must be in range [0, 1]!"
        self.timestamp        = timestamp
        self.timestep         = timestep
        self.historyEpoch     = historyEpoch
        self.significanceEpoch= historyEpoch/100
        self.numerator        = n
        self.denominator      = d
        self.finalized        = False
        self._key             = initial_key
        self._key_lock        = threading.Lock()

    def update_anamoly(self, current_timestamp, n):
        assert 0 <= n <= 1, "n must be in range [0, 1]!"
        with self._key_lock:
            self.numerator += n
            self.update_benign(current_timestamp)

    def update_benign(self, current_timestamp):
        self.denominator += 1
        if self.denominator > self.historyEpoch:
            self.denominator *= 0.8
            self.numerator   *= 0.8
        self.finalized = False

    def merge_history(self, other):
        with self._key_lock:
            self.numerator   += other.numerator
            self.denominator += other.denominator

    def decay_fraction(self, n):
        with self._key_lock:
            if self.numerator == 0:
                return True
            k = 1 - (n/self.numerator)
            self.numerator   *= k
            self.denominator *= k
            if self.denominator < 1:
                self.numerator = 0
                self.denominator = 1
            elif self.numerator < 0:
                self.numerator = 0
            return self.numerator == 0

    def set_score(self):
        self.finalized = True
        self.score     = self.numerator / self.denominator

    def get_score(self):
        if not self.finalized:
            self.set_score()
        return self.score

    def __lt__(self, other):
        return self.get_score() < other.get_score()

    def __eq__(self, other):
        return self.get_score() == other.get_score()

    def __repr__(self):
        try:
            return "\t{:.2f}\n".format(self.get_score())
        except Exception:
            traceback.print_exc()
            return "{num:.2f}/{den:.2f}\n".format(num=self.numerator, den=self.denominator)


class nodeScore():
    """docstring for nodeScore"""
    def __init__(self, max_length=100, mode='parallel',
                 name=None,
                #  endpoint='http://172.21.219.232:7654/api/scores'):
                endpoint='http://127.0.0.1:7654/api/scores'):
        self.max_length      = max_length
        self.scores          = dict()
        self.last_timestamp  = 0
        self.zeroed_node     = True
        self.endpoint        = endpoint
        self.mode            = mode
        if name:
            self.name = name
        else:
            letters    = string.ascii_lowercase
            self.name  = 'IDS'.join(random.choice(letters) for i in range(4))

    def update(self, nodeId, current_timestamp, n):
        self.last_timestamp = current_timestamp
        try:
            if n == 0:
                self.scores[nodeId].update_benign(current_timestamp)
                self.zeroed_node = nodeId
            else:
                self.scores[nodeId].update_anamoly(current_timestamp, n)
                self.zeroed_node = None
        except KeyError:
            if len(self.scores) < self.max_length:
                self.scores[nodeId] = scoreClass(current_timestamp, n)
                self.lookup_from_blockchain([nodeId])
            else:
                if not self.zeroed_node:
                    for nodeId_j in self.scores:
                        if self.scores[nodeId_j].decay_fraction(n):
                            self.zeroed_node = nodeId_j
                            break
                if self.zeroed_node:
                    try:
                        if self.scores[self.zeroed_node].denominator \
                           >= self.scores[self.zeroed_node].significanceEpoch:
                            self.backup_to_blockchain([self.get_score(self.zeroed_node)])
                        del self.scores[self.zeroed_node]
                    except Exception:
                        traceback.print_exc()
                        pdb.set_trace()
                    self.scores[nodeId] = scoreClass(current_timestamp, n)
                    self.lookup_from_blockchain([nodeId])
                    self.zeroed_node = None

    def get_score(self, nodeId):
        return [nodeId, self.scores[nodeId].numerator, self.scores[nodeId].denominator]

    def get_transaction_id(self):
        return self.name + str(self.last_timestamp)

    def request_builder(self, scores, timestamp, addScore=False):
        letters = string.ascii_lowercase
        unique  = ''.join(random.choice(letters) for _ in range(4))
        mode    = "addScore" if addScore else "getScore"

        data = "[\n"
        valid = False

        for score in scores:
            # ‣ Skip empty/malformed entries
            try:
                node_part = score[0] if addScore else score
            except Exception:
                continue
            node_id = str(node_part).strip()
            if not node_id:
                continue

            valid = True
            tx_id = f"IDS{unique}_{node_id}_{timestamp}"
            data += "{\n\"id\":\"" + tx_id + \
                    "\",\n\"execer\": \"admin:admin\",\n" + \
                    f"\"messageType\":\"{mode}\",\n\"digsig\":\"\""

            if addScore:
                data += ",\n\"userId\":\"" + str(score[0]) + \
                        "\",\n\"numerator\":" + str(score[1]) + \
                        ",\n\"denominator\":" + str(score[2])
            else:
                data += ",\n\"userId\":\"" + node_id + "\""

            data += "\n},"

        if not valid:
            return None

        data = data[:-1] + "\n]"
        if len(scores) == 1:
            data = data[1:-1]
        return data

    def backup_to_blockchain(self, scores):
        if self.mode == 'offline':
            return
        elif self.mode == 'blocking':
            self.backup_routine(scores)
        else:
            _thread.start_new_thread(self.backup_routine, (scores,))

    def backup_routine(self, scores):
        data_request = self.request_builder(scores, self.last_timestamp, addScore=True)
        if data_request is None:
            return
        attempts = 0
        while attempts < 3:
            try:
                response = requests.post(self.endpoint, data=data_request)
                response_json = response.json()
                if response_json.get('msg') in ('score added', 'scores added'):
                    return
                else:
                    raise ValueError(response_json.get('msg'))
            except Exception:
                attempts += 1
                time.sleep(1)

    def lookup_from_blockchain(self, identities):
        if self.mode == 'offline':
            return
        elif self.mode == 'blocking':
            self.lookup_routine(identities)
        else:
            _thread.start_new_thread(self.lookup_routine, (identities,))

    def lookup_routine(self, identities):
        data_request = self.request_builder(identities, self.last_timestamp)
        if data_request is None:
            return
        try:
            response = requests.post(self.endpoint, data=data_request)
            response_json = response.json()
            if response_json.get('msg') == 'not found':
                return
            ts = response_json['timestamp']
            n  = response_json['numerator']
            d  = response_json['denominator']
            past_score = scoreClass(ts, n, d)
            try:
                self.scores[identities[0]].merge_history(past_score)
            except KeyError:
                pass
        except Exception:
            pass

    def finalize(self):
        scores = []
        for nodeId in self.scores:
            self.scores[nodeId].set_score()
            scores.append(self.get_score(nodeId))
        self.backup_to_blockchain(scores)

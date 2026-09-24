#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script d'action d'alerte Splunk -> Microsoft Sentinel
Envoie les resultats d'une alerte Splunk vers la table custom de Sentinel
via l'API Log Analytics Data Collector.

Placement : /opt/splunk/etc/apps/search/bin/send_to_sentinel.py
Utilisation comme action d'alerte "Exécuter un script".

Configuration requise (variables d'environnement) :
    SENTINEL_WORKSPACE_ID   ID du workspace Log Analytics
    SENTINEL_SHARED_KEY     Clé partagée (primaire ou secondaire) du workspace

Exemple (à mettre dans le profil du compte qui exécute Splunk, jamais dans ce fichier) :
    export SENTINEL_WORKSPACE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    export SENTINEL_SHARED_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=="
"""

import sys
import os
import json
import requests
import datetime
import hashlib
import hmac
import base64
import gzip
import csv

# ============================================================
#  CONFIGURATION — lue depuis l'environnement, jamais en dur ici
# ============================================================
WORKSPACE_ID = os.environ.get("SENTINEL_WORKSPACE_ID")
SHARED_KEY   = os.environ.get("SENTINEL_SHARED_KEY")
LOG_TYPE     = "SplunkAlerts"   # deviendra SplunkAlerts_CL dans Sentinel
# ============================================================


def build_signature(workspace_id, shared_key, date, content_length,
                    method, content_type, resource):
    """Construit la signature d'authentification requise par l'API Sentinel."""
    x_headers = 'x-ms-date:' + date
    string_to_hash = (method + "\n" + str(content_length) + "\n" +
                      content_type + "\n" + x_headers + "\n" + resource)
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    authorization = "SharedKey {}:{}".format(workspace_id, encoded_hash)
    return authorization


def post_to_sentinel(workspace_id, shared_key, body, log_type):
    """Envoie les donnees (JSON) vers l'API Log Analytics."""
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)

    signature = build_signature(workspace_id, shared_key, rfc1123date,
                                content_length, method, content_type, resource)

    uri = ('https://' + workspace_id + '.ods.opinsights.azure.com' +
           resource + '?api-version=2016-04-01')

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri, data=body, headers=headers)
    if 200 <= response.status_code <= 299:
        print("Donnees envoyees a Sentinel avec succes (HTTP {}).".format(response.status_code))
    else:
        print("Echec de l'envoi. Code HTTP: {} - {}".format(response.status_code, response.text))


def read_splunk_results():
    """
    Splunk passe les resultats de l'alerte via un fichier CSV gzippe,
    dont le chemin est fourni en 8eme argument (sys.argv[8]).
    """
    if len(sys.argv) >= 9:
        results_file = sys.argv[8]
        rows = []
        try:
            with gzip.open(results_file, 'rt') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    clean_row = {k: v for k, v in row.items() if not k.startswith('__')}
                    rows.append(clean_row)
        except Exception as e:
            print("Erreur lecture resultats: {}".format(e))
        return rows
    return []


if __name__ == "__main__":
    if not WORKSPACE_ID or not SHARED_KEY:
        print("Erreur : SENTINEL_WORKSPACE_ID et/ou SENTINEL_SHARED_KEY non definis "
              "dans l'environnement. Le script s'arrete pour eviter un envoi rate.")
        sys.exit(1)

    results = read_splunk_results()

    if not results:
        results = [{"message": "Alerte Splunk declenchee (aucun detail disponible)",
                    "timestamp": datetime.datetime.utcnow().isoformat()}]

    body = json.dumps(results)
    post_to_sentinel(WORKSPACE_ID, SHARED_KEY, body, LOG_TYPE)

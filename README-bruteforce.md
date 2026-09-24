# 🛡️ Projet SOC — Brute Force : détection, remontée Sentinel, réponse automatique

**Compétences démontrées :** détection basée sur la volumétrie d'échecs d'authentification sur un même compte, réponse différenciée selon la nature du compte compromis, gestion du risque de désactivation d'un compte à privilèges.

**Technologies :** Splunk · Microsoft Sentinel · Azure Automation · PowerShell · NetExec · Active Directory · Entra ID

Même lab que le [scénario Kerberoasting](./README-kerberoasting.md) (`Mars.local.com`) — même pipeline Splunk → Sentinel → Azure Automation (détaillé dans le README), mais **signal** et **réponse** différents.

---

## Table des matières

1. [De quoi il s'agit](#-de-quoi-il-sagit)
2. [Stack technique](#-stack-technique)
3. [Attaque simulée](#-attaque-simulée)
4. [Détection](#-détection)
5. [Remontée vers Sentinel](#-remontée-vers-sentinel)
6. [Réponse automatisée](#-réponse-automatisée)
7. [Vérification](#-vérification)
8. [Problèmes rencontrés et solutions](#-problèmes-rencontrés-et-solutions)
9. [Pistes d'amélioration](#-pistes-damélioration)
10. [Résumé](#-résumé)

---

## 📌 De quoi il s'agit

Le Brute Force ([T1110.001](https://attack.mitre.org/techniques/T1110/001/), Credential Access) consiste à tester un grand nombre de mots de passe contre un **même compte**, jusqu'à trouver le bon. Cibler un compte unique avec un grand volume de tentatives risque de déclencher un verrouillage AD si une politique de lockout est configurée — c'est un signal en soi, en plus de l'accumulation d'échecs.

Contrairement à Kerberoasting, il n'y a pas de ticket Kerberos en jeu ici : le signal, c'est l'accumulation d'échecs d'authentification (Event **4625**) sur un même compte, depuis une même source, en peu de temps.

**Réponse retenue :** désactiver le compte ciblé (`Disable-ADAccount`), pas réinitialiser son mot de passe. Contrairement à `svc-sql` dans le scénario Kerberoasting (un compte applicatif qui doit rester actif), un compte utilisateur visé par un brute force n'a aucune raison de rester actif tant que l'incident n'est pas traité manuellement — la désactivation est le choix le plus sûr par défaut.

### MITRE ATT&CK

| Champ | Valeur |
|-------|--------|
| Technique | **[T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)** |
| Tactique | Credential Access |

---

## 🧰 Stack technique

| Composant | Rôle |
|-----------|------|
| **Active Directory** `Mars.local.com` | Compte ciblé |
| **DC** `WIN-UFUVI4HLPLO` (`192.168.1.100`) | Journal Security, Hybrid Worker |
| **Kali Linux** (`192.168.1.50`) | Attaque (NetExec) |
| **Splunk Enterprise** | Détection (recherche planifiée + script d'action — voir README) |
| **Microsoft Sentinel** | Table `SplunkAlerts_CL` → incident → playbook |
| **Azure Automation** | Runbook PowerShell `disable-account`, exécuté sur le DC |
| **Entra Connect** | Synchro du compte après désactivation |

**Compte de test :** `CATHY_MONROE`

---

## 💥 Attaque simulée

Premier essai en SMB : timeout systématique dans ce lab (voir [problèmes](#-problèmes-rencontrés-et-solutions)). Bascule sur LDAP, qui passe sans souci.

```bash
nxc ldap 192.168.1.100 -u CATHY_MONROE -p passwords.txt -d Mars.local.com
```

Chaque tentative ratée génère un Event **4625** sur le DC.

![Attaque NetExec LDAP](./Capture%20d'écran%202026-09-24%20122201.png)

---

## 🔍 Détection

L'audit des échecs de connexion (sous-catégorie **Ouverture de session**, GUID `{0CCE9215-69AE-11D9-BED3-505054503030}`) doit être activé **dans la GPO des contrôleurs de domaine**, pas en local — même piège d'écrasement que pour l'audit Kerberos.



Un Event **4625** contient deux champs « Nom du compte » : celui du sujet (le compte système, ex. `WIN-UFUVI4HLPLO$`) et celui du compte pour lequel l'ouverture de session a échoué — c'est **ce second champ**, pas le premier, qui identifie le compte réellement ciblé.

```spl
index=main source="WinEventLog:Security" EventCode=4625
| rex field=_raw "Compte pour lequel.*?ouverture de session a.*?Nom du compte :\s+(?<account>\S+)"
| rex field=_raw "Adresse du réseau source :\s+(?<src_ip>\S+)"
| stats count by account, src_ip
| where count > 5
| eval attack_type="Brute_Force"
```

Le seuil (`count > 5`) est arbitraire pour le lab — dans un environnement réel, il se calibre sur le taux de faux positifs observé (oublis de mot de passe légitimes).

![Recherche Splunk — événements 4625](./Capture%20d'écran%202026-09-24%20122520.png)

---

## 📡 Remontée vers Sentinel

Même mécanisme que Kerberoasting (`send_to_sentinel.py` → API Data Collector → table `SplunkAlerts_CL`, détaillé dans le README).

Règle d'analytique Sentinel, filtrée sur ce scénario précis :

```kql
SplunkAlerts_CL
| where attack_type_s == "Brute_Force"
```

**Entity mapping :** `account_s` → Account, `src_ip_s` → IP. Il n'y a ici qu'un seul compte extrait par la recherche SPL (le compte ciblé) — pas d'ambiguïté possible entre compte attaquant et compte visé au niveau du mapping.

![Règle d'analytique Sentinel — Brute_Force](./Capture%20d'écran%202026-09-24%20121000.png)

---

## 🤖 Réponse automatisée

Le playbook suit la même structure que Kerberoasting (Get Accounts → For each → Create job), avec le runbook `disable-account` :

![Playbook Logic App — disable-account](./Capture%20d'écran%202026-08-28%20142553.png)

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$AccountName
)

Import-Module ActiveDirectory

try {
    Disable-ADAccount -Identity $AccountName
    Write-Output "Compte $AccountName désactivé dans l'AD local."
}
catch {
    Write-Output "Erreur : $_"
}

try {
    Import-Module ADSync
    Start-ADSyncSyncCycle -PolicyType Delta
    Write-Output "Synchronisation Entra Connect déclenchée."
}
catch {
    Write-Output "Note : synchro au prochain cycle. $_"
}
```

Le runbook doit tourner en **Runtime PowerShell 5.1**, pas 7.2 — le module `ActiveDirectory` n'y est pas reconnu (voir [problèmes](#-problèmes-rencontrés-et-solutions)).

---

## ✅ Vérification

Incident créé, playbook réussi.

![Incident Sentinel](./Capture%20d'écran%202026-09-24%20125744.png)

![Exécution du playbook](./Capture%20d'écran%202026-09-24%20125833.png)

```powershell
Get-ADUser -Identity  CATHY_MONROE -Properties Enabled, whenChanged | Select-Object Name, Enabled, whenChanged
```

Doit renvoyer `Enabled : False`.

![Get-ADUser — Enabled False](./Capture%20d'écran%202026-09-24%20130157.png)

Confirmation côté Entra ID après synchro.

![Compte désactivé dans Entra ID](./Capture%20d'écran%202026-09-24%20130647.png)

---

## 🧩 Problèmes rencontrés et solutions

### Problème 1 — SMB timeout à l'attaque

**Symptôme :** NetExec timeout systématiquement en SMB.

**Cause :** comportement du build Windows / signing activé.

**Solution :** bascule sur le protocole LDAP.

---

### Problème 2 — Mauvais champ « Nom du compte » extrait

**Symptôme :** le compte extrait par la regex était le compte système du DC, pas le compte ciblé.

**Cause :** un Event 4625 contient deux champs « Nom du compte » (sujet + compte ciblé) ; la regex initiale prenait le premier.

**Solution :** cibler spécifiquement la section « Compte pour lequel l'ouverture de session a échoué ».

---

### Problème 3 — `Disable-ADAccount` introuvable dans le runbook

**Symptôme :** échec du runbook, commande non reconnue.

**Cause :** le module `ActiveDirectory` n'est pas disponible en PowerShell 7.2 sur ce DC.

**Solution :** création du runbook en Runtime 5.1.

---

### Tableau récapitulatif

| # | Blocage | Cause | Fix |
|---|---------|-------|-----|
| 1 | SMB timeout | Signing / build Windows | Attaque via LDAP |
| 2 | Mauvais « Nom du compte » | Deux champs dans le 4625 | Regex sur le compte ciblé |
| 3 | `Disable-ADAccount` KO | Runbook PS 7.2 | Runtime PowerShell 5.1 |

---

## 🚀 Pistes d'amélioration

- [ ] **Garde-fou anti-admin :** exclure explicitement les comptes à privilèges d'une désactivation automatique
- [ ] **Enrichissement Threat Intelligence :** vérifier l'IP source (AbuseIPDB, VirusTotal) avant d'agir
- [ ] **Détection de compromission :** repérer un pattern 4625 répétés suivis d'un 4624 réussi (mot de passe trouvé)
- [ ] **Migration** vers la Logs Ingestion API (l'API Data Collector est en dépréciation)

---

## 🎯 Résumé

Même chaîne SOC que Kerberoasting, **signal différent** (4625 vs 4769) et **réponse différente** (désactivation vs rotation de mot de passe) — le choix de réponse s'adapte à la nature du compte touché, pas appliqué mécaniquement partout.

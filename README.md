# Password Manager
![Run Tests](https://github.com/Coding-Crashkurse/Software-Engineering-Capstone-Project/actions/workflows/main.yaml/badge.svg)


Der Password Manager ist ein einfaches und sicheres Tool, um Passwörter zu verwalten. Es ermöglicht das Erstellen, Speichern, Abrufen und Löschen von Passwörtern für verschiedene Dienste. Die Passwörter werden verschlüsselt gespeichert, um die Sicherheit der Daten zu gewährleisten.

## Features

- Benutzerregistrierung und Anmeldung
- Passwörter erstellen, speichern, abrufen, aktualisieren und löschen
- Passwörter werden verschlüsselt gespeichert
- Kommandozeilenbasierte Benutzeroberfläche
- Benutzerfreundliche Tabellenanzeige für gespeicherte Passwörter

## GitHub Actions

Dieses Projekt verwendet GitHub Actions für Continuous Integration und Continuous Deployment. Es führt automatisch Tests und Code-Qualitätsprüfungen durch, um sicherzustellen, dass das Projekt fehlerfrei und stabil ist.

## Pre-commit Hooks

Um die Code-Qualität zu verbessern und konsistent zu halten, verwendet dieses Projekt pre-commit-hooks. Diese Hooks überprüfen den Code automatisch vor jedem Commit und stellen sicher, dass er den festgelegten Standards entspricht. Dazu gehören Tests, Linting, Formatierung und vieles mehr.

## Unit Tests

Das Projekt verwendet Unit Tests, um sicherzustellen, dass alle Funktionen korrekt funktionieren und keine Fehler enthalten. Die Tests werden automatisch von GitHub Actions ausgeführt und bieten eine Sicherheitsstufe, um sicherzustellen, dass Änderungen am Code keine unbeabsichtigten Auswirkungen haben.

## Installation und Verwendung

Um den Password Manager zu installieren und verwenden, führe die folgenden Schritte aus:

1. Klone das Repository auf deinen lokalen Rechner:

```shell
git clone https://github.com/yourusername/password-manager.git
```

2. Wechsle in das Verzeichnis des Projekts:

```shell
cd password-manager
```

3. Installiere die Abhängigkeiten mit Poetry:

```shell
poetry install
```

4. Aktiviere die virtuelle Umgebung:

```shell
poetry shell
```

5. Initialisiere das Projekt:

```shell
password-manager init
```


6. Führe die verfügbaren Befehle aus, um den Password Manager zu verwenden. Zum Beispiel, um einen neuen Benutzer zu erstellen:


```shell
password-manager create_user
password-manager --help # Hilfe
```

Viel Spaß! :-)
"""guardai - defensiver Schwachstellen- und Anomalie-Scanner.

Bewusst KEIN "Zero-Day-Schutz per Signatur": Zero-Days stehen in keiner
Datenbank. guardai kombiniert stattdessen zwei reale Ansaetze:

1. Bekannte Schwachstellen (CVEs) aus oeffentlichen Feeds (NVD, OSV.dev)
   werden gegen die Abhaengigkeiten eines Repos geprueft.
2. Ein unueberwachtes ML-Modell (Isolation Forest) markiert *auffaellige*
   Dateien, die von der Norm des Projekts abweichen - das ist die einzig
   ehrliche Heuristik fuer noch unbekannte Bedrohungen.
"""

__version__ = "0.1.0"

# Tests du responder

```bash
python3 tests/test_responder.py        # aucune dépendance
python3 -m pytest tests -v             # si pytest est installé
```

- 25 tests : moteur de décision, validation de la politique, ordres du dashboard,
  statut, et **démon complet** (arrêt propre, redémarrage, entrées invalides).
- Les tests du démon utilisent un **faux `nft`** créé à la volée : aucun vrai
  pare-feu n'est modifié. Ils demandent Linux (ignorés sous Windows) ; lance-les
  sur la VM pour les passer tous.

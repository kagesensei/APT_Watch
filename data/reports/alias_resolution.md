# Alias resolution report

Generated 2026-09-14 by `resolve/aliases.py`, matching 176 ATT&CK actors against 1052 MISP Galaxy threat-actor cluster entries (2463 alias rows).

## Summary

- Matched exactly, 1-to-1 (written to `actor_xwalk`): **115**
- Ambiguous: one ATT&CK group matched >1 MISP UUID: **28**
- Ambiguous: one MISP UUID matched >1 ATT&CK group: **11**
- Unmatched, with a fuzzy candidate >= 90 for review (in `actor_xwalk_candidates`): **3**
- Completely unmatched (no exact match, no fuzzy candidate >= 90): **12**

## Unmatched ATT&CK groups (12)

No exact match after normalization, and no fuzzy candidate scored >= 90 against any MISP entry.

| ATT&CK ID | Name | STIX ID |
|---|---|---|
| G0011 | PittyTiger | intrusion-set--fe98767f-9df8-42b9-83c9-004b1dec8647 |
| G0028 | Threat Group-1314 | intrusion-set--d519164e-f5fa-4b8c-a1fb-cf0172ad0983 |
| G0089 | The White Company | intrusion-set--6688d679-ccdb-4f12-abf6-c7545dd767a4 |
| G0108 | Blue Mockingbird | intrusion-set--73a80fab-2aa3-48e0-a4d0-3a4828200aee |
| G0124 | Windigo | intrusion-set--4e868dad-682d-4897-b8df-2dc98f46c68a |
| G0140 | LazyScripter | intrusion-set--abc5a1d4-f0dc-49d1-88a1-4a80e478bb03 |
| G1032 | INC Ransom | intrusion-set--cb41e991-65f4-4668-a65f-f4200545b5a1 |
| G1040 | Play | intrusion-set--ecbf507f-6786-4121-a4cc-0fd6a8d3a29d |
| G1043 | BlackByte | intrusion-set--02b16bd6-ae88-417a-8a3f-02c5e166175a |
| G1047 | Velvet Ant | intrusion-set--e1fc262c-dad2-4b82-abda-5f08dd134971 |
| G1050 | Water Galura | intrusion-set--be8847e0-9512-45db-895e-f871ab6d3820 |
| G1051 | Medusa Group | intrusion-set--918da025-04bd-48af-b6c4-f3e4d1b915eb |

## Fuzzy candidates (3) -- NOT written to `actor_xwalk`; review and promote manually

| Score | ATT&CK ID | ATT&CK name | Matched ATT&CK alias | MISP name | Matched MISP alias | MISP UUID |
|---|---|---|---|---|---|---|
| 100 | G0114 | Chimera | Chimera | WET PANDA | Red Chimera | ba8973b2-fd97-4aa7-9307-ea4838d96428 |
| 100 | G0020 | Equation | Equation | Equation Group | Equation Group | 7036fb3d-86b7-4d9c-bc66-1e1ead8b7840 |
| 95 | G0142 | Confucius | Confucius | Confucious | Confucious | 54618130-55d3-4506-b62b-67f2dca12b04 |

## Ambiguous matches

### One ATT&CK group matches more than one MISP UUID (28)

- G0004 Ke3chang (intrusion-set--6713ab67-e25b-49cc-808d-2b36d4fbc35c) matches: APT15 (3501fbf2-098f-47e7-be6a-6b0ff5742ce8), GREF (e6d16c22-0780-483c-9920-c1d9f27b10c8)
- G0010 Turla (intrusion-set--7a19ecb1-3c65-4de3-a230-993516aed6a6) matches: White Bear (dc6c6cbc-9dc6-4ace-a2d2-fadefe45cce6), Turla (fa80877c-f509-4daf-8b62-20aba1635f68)
- G0016 APT29 (intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542) matches: UNC2452 (2ee5ed7a-c4d0-40be-a837-20817474a15b), APT29 (b2056ff0-00b9-482e-b11c-c771daa5f28a), UNC3524 (bee8b09c-07e5-4c12-94d6-266ebcb1ec24)
- G0030 Lotus Blossom (intrusion-set--88b7dbc2-32d3-4e31-af2f-3fc24e1582d7) matches: LOTUS PANDA (32fafa69-fe3c-49db-afd4-aac2664bcf0d), Raspberry Typhoon (37f012df-54d8-4b3d-a288-af47240430ea), Thrip (98be4300-a9ef-11e8-9a95-bb9221083cfc)
- G0034 Sandworm Team (intrusion-set--381fcf73-60f6-4ab2-9991-6af3cbc35192) matches: IRIDIUM (29cfe970-5446-4cfc-a2da-00e9f49e02ba), Sandworm (f512de42-f76b-40d2-9923-59e7dbdfec35)
- G0040 Patchwork (intrusion-set--17862c7d-9e60-48a0-b48e-da4dc4c3f6b0) matches: QUILTED TIGER (18d473a5-831b-47a5-97a1-a32156299825), VICEROY TIGER (e2b87f81-a6a1-4524-b03f-193c3191d239)
- G0049 OilRig (intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d) matches: OilRig (42be2a84-5a5c-4c6d-9864-3f09d75bb0ba), Cleaver (86724806-7ec9-4a48-a0a7-ecbde3bf4810), CHRYSENE (a0082cfa-32e2-42b8-92d8-5c7a7409dcf1)
- G0059 Magic Hound (intrusion-set--f9d6633a-55e6-4adc-9263-6ae080421a13) matches: APT35 (b8967b3c-3bc9-11e8-8701-8b1ead8c099e), TA453 (c1d44f44-425e-48fd-b78b-84b988da8bc3), Charming Kitten (f98bac6b-12fd-4cad-be84-c84666932232)
- G0082 APT38 (intrusion-set--00f67a77-86a4-4adf-be26-1a54fc713340) matches: Lazarus Group (68391641-859f-4a9a-9a1e-3e5cf71ec376), STARDUST CHOLLIMA (d8e1762a-0063-48c2-9ea1-8d176d14b70f)
- G0092 TA505 (intrusion-set--7eda3dd8-b09b-4705-8090-c2ad9fb8c14d) matches: TA505 (03c80674-35f8-4fe0-be2b-226ed0fcd69f), MONTY SPIDER (168a9e38-70e3-4542-b78f-afa2414436bb)
- G0094 Kimsuky (intrusion-set--0ec2f388-bf0f-4b5c-97b1-fc736d26c25f) matches: APT43 (aac49b4e-74e9-49fa-84f9-e340cf8bafbc), Kimsuky (bcaaad6f-0597-4b89-b69b-84a6be2b7bc3)
- G0102 Wizard Spider (intrusion-set--dd2d9ca6-505b-4860-a604-233685b802c7) matches: UNC1878 (3c2bb7d7-a085-4594-adc7-4a20cf724abb), GRIM SPIDER (3cf6dbb5-bf9e-47d4-a8d5-b6d76f5a791f), WIZARD SPIDER (bdf4fe4f-af8a-495f-a719-cf175cecda1f)
- G0112 Windshift (intrusion-set--afec6dc3-a18e-4b62-b1a4-5510e1a498d1) matches: WindShift (cbbbfc82-9294-11e9-8e19-2bc14137b25b), Bahamut (dc3edacc-bb24-11e8-81fb-8c16458922a7)
- G0115 GOLD SOUTHFIELD (intrusion-set--c77c5576-ca19-42ed-a36f-4b4486a84133) matches: GOLD SOUTHFIELD (262c8537-1cdb-4297-aa3e-1410164160bf), PINCHY SPIDER (80f07c15-cad3-44a2-a8a4-dd14490b5117)
- G0119 Indrik Spider (intrusion-set--01e28736-2ffc-455b-9880-ed4d1407ae07) matches: INDRIK SPIDER (658314bc-3bb8-48d2-913a-c528607b75c8), Evil Corp (c30fbdc8-b66d-4242-a02a-e01946bc86d8)
- G0123 Volatile Cedar (intrusion-set--b2e34388-6938-4c59-a702-80dc219e15e3) matches: Volatile Cedar (cf421ce6-ddfe-419a-bc65-6a9fc953232a), Amethyst Rain (ee12e0a9-a20b-4d48-8814-d565211cb0ba)
- G0129 Mustang Panda (intrusion-set--420ac20b-f2b9-42b8-aa1a-6d4b72895ca4) matches: MUSTANG PANDA (78bf726c-a9e6-11e8-9e43-77249a2f7339), Camaro Dragon (9ee446fd-b0cd-4662-9cd1-a60b429192db), UNC6384 (a3e4a57e-4b50-4bca-9282-3307e92e5539), RedDelta (fceed509-938e-4f9e-acd4-76e6c28dc6f1)
- G0130 Ajax Security Team (intrusion-set--fa19de15-6169-428d-9cd6-3ca3d56075b7) matches: Flying Kitten (ba724df5-9aa0-45ca-8e0e-7101c208ae48), Rocket Kitten (f873db71-3d53-41d5-b141-530675ade27a)
- G0138 Andariel (intrusion-set--39d6890e-7f23-4474-b8ef-e7b0343c5fc8) matches: Silent Chollima (245c8dde-ed42-4c49-b48b-634e3e21bdd7), Lazarus Group (68391641-859f-4a9a-9a1e-3e5cf71ec376)
- G1003 Ember Bear (intrusion-set--a7f57cc1-4540-4429-823f-f4e56b8473c9) matches: DEV-0586 (a5f64c1a-c829-4855-903d-e0ff2098b2d7), SaintBear (c67d3dfb-ab39-46e1-a971-5efdfe6a5b9f)
- G1020 Mustard Tempest (intrusion-set--0d4ac089-ced4-4cc4-a989-174d08e6d030) matches: Mustard Tempest (3ce9610b-2435-4c41-80d1-3f95a5ff2984), GOLD PRELUDE (8134c96d-d6ed-49cc-99d6-fe74c0636387)
- G1023 APT5 (intrusion-set--c1aab4c9-4c34-4f4f-8541-d529e46a07f9) matches: UNC2630 (86dfe64e-7101-4d45-bb94-efc40c5e14fe), APT5 (a47b79ae-7a0c-4308-9efc-294af19cc795)
- G1028 APT-C-23 (intrusion-set--8332952e-b86b-486b-acc3-1c2a85d39394) matches: AridViper (0cfff0f4-868c-40a1-b9b4-0d153c0b33b6), Pinstripe Lightning (543bdc9f-da35-4c4b-9433-06cbd3091772)
- G1033 Star Blizzard (intrusion-set--9b36c218-4d80-4ec6-a68d-cc2886bbe410) matches: Cold River (7d99d2f7-adf0-44e4-9044-d18ff6842a16), Callisto (fbd279ab-c095-48dc-ba48-4bece3dd5b0f)
- G1034 Daggerfly (intrusion-set--f3be6240-f68e-47e1-90d2-ad8f3b3bb8a6) matches: Evasive Panda (171d0590-be92-443f-addb-af5dc2a8034d), BRONZE HIGHLAND (62710572-e416-419d-bb1f-81ffc1ddc976)
- G1049 AppleJeus (intrusion-set--14225573-63b5-4e50-ba9a-5fdcaf6a7b4c) matches: Lazarus Group (68391641-859f-4a9a-9a1e-3e5cf71ec376), UNC4736 (afe5526e-e5e4-4b05-bc69-2bfb6785fc7e)
- G1052 Contagious Interview (intrusion-set--46599a4a-77ee-4697-9474-2683b6464859) matches: WageMole (09aa3edb-e956-43f0-9fcb-a3154b47d202), Contagious Interview (b2765bd8-1200-4df5-a9d3-72a7b679dcdb)
- G1055 VOID MANTICORE (intrusion-set--ebd7ce77-c9ba-4fba-bb28-58296ac66559) matches: BANISHED KITTEN (3682a08e-c1d9-4dff-ae08-774883dddba6), Void Manticore (53ac2695-35ba-4ab2-a5cd-48ca533f1b72), HomeLand Justice (bfc538e1-9205-420a-8641-6292023ecd08)

### One MISP UUID matches more than one ATT&CK group (11)

- FIN7 (00220228-a5a4-4032-a30d-826bb55aa3fb) matches: G0046 FIN7 (intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc), G0008 Carbanak (intrusion-set--55033a4d-3ffe-46b2-99b4-2c1541e9ce1c)
- APT19 (066d25c1-71bd-4bd4-8ca7-edbba00063f4) matches: G0009 Deep Panda (intrusion-set--a653431d-6a5e-4600-8ad3-609b5af57064), G0073 APT19 (intrusion-set--fe8796a4-2a02-41a0-9d27-7aa1e995feb6)
- Earth Lusca (39150b30-61af-4d9c-9682-1595e145f3c1) matches: G0143 Aquatic Panda (intrusion-set--64b52e7d-b2c4-4a02-9372-08a463f5dc11), G1006 Earth Lusca (intrusion-set--cc613a49-9bfa-4e22-98d1-15ffbb03f034)
- Lazarus Group (68391641-859f-4a9a-9a1e-3e5cf71ec376) matches: G0082 APT38 (intrusion-set--00f67a77-86a4-4adf-be26-1a54fc713340), G1049 AppleJeus (intrusion-set--14225573-63b5-4e50-ba9a-5fdcaf6a7b4c), G0138 Andariel (intrusion-set--39d6890e-7f23-4474-b8ef-e7b0343c5fc8), G0032 Lazarus Group (intrusion-set--c93fccb1-e8e8-42cf-ae33-2ad1d183913a), G1036 Moonstone Sleet (intrusion-set--e6db1e55-b199-4b6b-8633-989345ee45e0)
- MUSTANG PANDA (78bf726c-a9e6-11e8-9e43-77249a2f7339) matches: G0129 Mustang Panda (intrusion-set--420ac20b-f2b9-42b8-aa1a-6d4b72895ca4), G1014 LuminousMoth (intrusion-set--b7f627e2-0817-4cd5-8d50-e75f8aa85cc6)
- Cleaver (86724806-7ec9-4a48-a0a7-ecbde3bf4810) matches: G0049 OilRig (intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d), G0003 Cleaver (intrusion-set--8f5e8dc7-739d-4f5e-a8a1-a66e004d7063)
- Thrip (98be4300-a9ef-11e8-9a95-bb9221083cfc) matches: G0030 Lotus Blossom (intrusion-set--88b7dbc2-32d3-4e31-af2f-3fc24e1582d7), G0076 Thrip (intrusion-set--d69e568e-9ac8-4c08-b32c-d93b43ba9172)
- APT17 (99e30d89-9361-4b73-a999-9e5ff9320bcb) matches: G0025 APT17 (intrusion-set--090242d7-73fc-4738-af68-20162f7a5aae), G0001 Axiom (intrusion-set--a0cb9370-e39b-44d5-9f50-ef78e412b973)
- APT41 (9c124874-042d-48cd-b72b-ccdc51ecbbd6) matches: G0096 APT41 (intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7), G0044 Winnti Group (intrusion-set--c5947e1c-1cbc-434c-94b8-27c7e3be0fff)
- DragonOK (a9b44750-992c-4743-8922-129880d277ea) matches: G0002 Moafee (intrusion-set--2e5d3a83-fe00-41a5-9b60-237efc84832f), G0017 DragonOK (intrusion-set--f3bdec95-3d62-42d9-a840-29630f6cdc1a)
- SaintBear (c67d3dfb-ab39-46e1-a971-5efdfe6a5b9f) matches: G1031 Saint Bear (intrusion-set--674582ec-51c4-42ce-b409-797239e37a2a), G1003 Ember Bear (intrusion-set--a7f57cc1-4540-4429-823f-f4e56b8473c9)

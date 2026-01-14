Détection de présence, Contrôle réseau, Surveillance énergétique

- Détection de présence basée sur la connexion WiFi ou Ethernet du smartphone
- Surveillez et contrôlez* votre/vos réseau(x) WiFi et ses appareils connectés
- Bloquez le WiFi de vos enfants après le dîner
- Surveillez la consommation d'énergie de vos appareils réseau, par ex. la TV

Voir et journaliser :
- statut de la connexion internet
- vitesse de téléchargement et d'envoi internet
- statut de connexion des appareils connectés
- qualité WiFi et bande passante par appareil
- consommation d'énergie par appareil

Agir sur :
- appareil se connectant ou se déconnectant (présence)
- changement de bande passante ou de lien wifi d'un appareil
- détection d'un appareil inconnu se connectant au réseau
- alarme lorsque la connexion internet est coupée
- changement de vitesse de téléchargement/envoi internet

Faire :
- envoyer WakeOnLan (WOL) à une adresse MAC*
- bloquer et autoriser un appareil connecté par adresse MAC*
- activer et désactiver le WiFi invité*
- redémarrer le routeur*

* Travaux en cours

Configuration du routeur dans Homey :
L'application est destinée aux routeurs OpenWRT fonctionnant en mode Routeur. Vous pouvez ajouter des routeurs OpenWRT configurés en mode Point d'Accès (AP) pour une meilleure/plus rapide détection des appareils wifi dans toute votre maison. Votre Homey doit être connecté à l'intérieur de la partie LAN du routeur, et non de l'extérieur (WAN). Au démarrage de l'application, Homey essaiera d'activer automatiquement les statistiques de trafic (vitesse de téléchargement/envoi) en installant le paquet nlbwmon.

Détection de présence :
Après avoir ajouté votre routeur à Homey, vous pouvez commencer à ajouter les appareils mobiles ou fixes que vous souhaitez suivre pour la présence.

Surveillance énergétique :
Après avoir ajouté votre routeur à Homey, vous pouvez ajouter des appareils supplémentaires que vous souhaitez surveiller pour la consommation, par ex. votre TV ou imprimante. Dans les paramètres avancés de l'appareil, entrez la consommation électrique estimée / moyenne de l'appareil lorsqu'il est ÉTEINT ou ALLUMÉ. Maintenant, lorsque vous allumez votre TV, vous verrez que la puissance estimée est incluse dans l'onglet Énergie de Homey.

Routeurs supportés :
Cette application a été développée et testée sur un routeur Netgear R7800 exécutant OpenWRT 24.10. Elle devrait être compatible avec tous les routeurs OpenWRT exécutant le firmware 24.10 ou supérieur.
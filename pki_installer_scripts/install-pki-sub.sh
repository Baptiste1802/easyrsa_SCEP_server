#!/bin/bash

# Variables
PKI_ADMIN_USER="subCAadmin"
PKI_HOME="/home/$PKI_ADMIN_USER/easy-rsa"
EASYRSA_PATH="/usr/share/easy-rsa/3"
EASYRSA_VARS_FILE="/home/$PKI_ADMIN_USER/easy-rsa/pki/vars.backup"
EASYRSA_VARS="/home/$PKI_ADMIN_USER/easy-rsa/pki/vars"
EASYRSA_CERT_NAME="Sub-CA"
PKI_ADMIN_PASS="rootroot"  # Mot de passe pour subCAadmin

# Couleurs
LIGHT_BLUE='\033[1;34m' # Bleu clair
GREEN='\033[1;32m'      # Vert
RED='\033[0;31m'        # Rouge
NC='\033[0m'            # Pas de couleur

# Définir les variables d'environnement Easy-RSA
export EASYRSA="$PKI_HOME"
export EASYRSA_PKI="$PKI_HOME/pki"  # ou utilisez --pki-dir lors de l'appel

# Création de la PKI Root
echo "Installation de Easy-RSA..."
dnf install -y epel-release
dnf install -y easy-rsa
echo -e "${GREEN}Easy-RSA installé avec succès.${RESET}"

# Créer un utilisateur administrateur PKI
echo "Création de l'utilisateur administrateur PKI..."
adduser $PKI_ADMIN_USER
echo "$PKI_ADMIN_USER:$PKI_ADMIN_PASS" | chpasswd
echo -e "${GREEN}Utilisateur administrateur PKI créé avec succès.${RESET}"

# Créer un répertoire qui contiendra les fichiers de notre PKI
echo "Création du répertoire pour la PKI..."
mkdir -p $PKI_HOME

# Copier les fichiers easy-rsa dans ce répertoire
echo "Copie des fichiers Easy-RSA dans le répertoire PKI..."
cp -r $EASYRSA_PATH/* $PKI_HOME/
echo -e "${GREEN}Fichiers Easy-RSA copiés avec succès.${RESET}"

# Initialiser la PKI
echo "Initialisation de la PKI..."
$PKI_HOME/easyrsa init-pki
echo -e "${GREEN}PKI initialisée avec succès.${RESET}"

# Modifier la configuration vars
echo "Sauvegarde de la configuration vars..."
mv $EASYRSA_VARS $EASYRSA_VARS_FILE

# Écrire les nouvelles variables de configuration dans vars
echo "Écriture des nouvelles variables de configuration dans vars..."
cat <<EOL > $EASYRSA_VARS
set_var EASYRSA_KEY_SIZE 2048
set_var EASYRSA_ALGO rsa
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 825
set_var EASYRSA_CRL_DAYS 100
set_var EASYRSA_DIGEST "sha256"
set_var EASYRSA_RAND_SN "yes"
set_var EASYRSA_PRE_EXPIRY_WINDOW 90
set_var EASYRSA_REQ_COUNTRY    "FR"
set_var EASYRSA_REQ_PROVINCE   "CVL"
set_var EASYRSA_REQ_CITY       "Bourges"
set_var EASYRSA_REQ_ORG        "insacvl"
set_var EASYRSA_REQ_EMAIL      "admin@example.com"
set_var EASYRSA_REQ_OU         "Community"
EOL
echo -e "${GREEN}Variables de configuration écrites avec succès.${RESET}"

# Création des fichiers utiles pour la PKI
echo "Création des fichiers utiles pour la PKI..."
mkdir /home/subCAadmin/easy-rsa/pki/issued
mkdir /home/subCAadmin/easy-rsa/pki/certs_by_serial
touch /home/subCAadmin/easy-rsa/pki/index.txt
echo "1000" > /home/subCAadmin/easy-rsa/pki/serial
echo "unique_subject = no" > /home/subCAadmin/easy-rsa/pki/index.txt.attr

# Changer les droits d’accès à la fin
echo "Changement des droits d'accès..."
chown -R $PKI_ADMIN_USER:$PKI_ADMIN_USER $PKI_HOME
chmod 600 -R $PKI_HOME
chmod u+x $PKI_HOME/
chmod u+x $PKI_HOME/pki
chmod u+x $PKI_HOME/easyrsa
chmod u+x $PKI_HOME/pki/certs_by_serial
chmod u+x $PKI_HOME/pki/inline
chmod u+x $PKI_HOME/pki/issued
chmod u+x $PKI_HOME/pki/private
chmod u+x $PKI_HOME/pki/reqs
chmod 705 $PKI_HOME/x509-types
echo -e "${GREEN}Droits d'accès changés avec succès.${RESET}"

echo -e "${GREEN}Script terminé avec succès.${RESET}"

# Instructions finales
echo -e "${LIGHT_BLUE}Changer d'utilisateur : 'su - subCAadmin' puis cd ~/easy-rsa/"
echo -e "${LIGHT_BLUE}Générer un couple clé publique/privée avec la commande './easyrsa gen-req sub-ca nopass' avec le CN 'Sub-CA'"
echo -e "${LIGHT_BLUE}Puis envoyer la req sur la RootCA afin de signer le certificat de la CA sub : 'scp /home/subCAadmin/easy-rsa/pki/reqs/sub-ca.req rootCAadmin@$IP:/home/rootCAadmin/easy-rsa/pki/reqs'"
echo -e "${LIGHT_BLUE}Sur la rootCA, signer la requête puis envoyer le certificat signé sur la PKI sub : '/home/rootCAadmin/easy-rsa/easyrsa sign-req ca sub-ca'"
echo -e "${LIGHT_BLUE}Sur la rootCA, envoyer le certificat signé sur la PKI sub : 'scp /home/rootCAadmin/easy-rsa/pki/issued/sub-ca.crt subCAadmin@$IP:/home/subCAadmin/easy-rsa/pki/ca.crt'"
echo -e "${LIGHT_BLUE}Sur la subCA, renommer et placer la private key à la racine du répertoire PKI : 'mv /home/subCAadmin/easy-rsa/pki/private/sub-ca.key /home/subCAadmin/easy-rsa/pki/ca.key'${RESET}"

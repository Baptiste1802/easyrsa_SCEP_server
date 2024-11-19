#!/bin/bash

# Couleurs
LIGHT_BLUE='\033[1;34m' # Bleu clair
GREEN='\033[1;32m'      # Vert
RED='\033[0;31m'        # Rouge
NC='\033[0m'            # Pas de couleur

# Variables
PKI_ADMIN_USER="rootCAadmin"
PKI_HOME="/home/$PKI_ADMIN_USER/easy-rsa"
EASYRSA_PATH="/usr/share/easy-rsa/3"
EASYRSA_VARS_FILE="/home/$PKI_ADMIN_USER/easy-rsa/pki/vars.backup"
EASYRSA_VARS="/home/$PKI_ADMIN_USER/easy-rsa/pki/vars"
EASYRSA_CERT_NAME="Root-CA"
PKI_ADMIN_PASS="rootroot"  # Mot de passe pour rootCAadmin

# Définir les variables d'environnement Easy-RSA
export EASYRSA="$PKI_HOME"
export EASYRSA_PKI="$PKI_HOME/pki"  # ou utilisez --pki-dir lors de l'appel

# Création de la PKI Root
echo "Installation de Easy-RSA..."
dnf install -y epel-release
dnf install -y easy-rsa
echo -e "${GREEN}Easy-RSA installé avec succès.${NC}"

# Créer un utilisateur administrateur PKI
echo "Création de l'utilisateur administrateur PKI..."
adduser $PKI_ADMIN_USER
echo "$PKI_ADMIN_USER:$PKI_ADMIN_PASS" | chpasswd
echo -e "${GREEN}Utilisateur administrateur PKI créé avec succès.${NC}"

# Créer un répertoire qui contiendra les fichiers de notre PKI
echo "Création du répertoire pour la PKI..."
mkdir -p $PKI_HOME

# Copier les fichiers easy-rsa dans ce répertoire
echo "Copie des fichiers Easy-RSA dans le répertoire PKI..."
cp -r $EASYRSA_PATH/* $PKI_HOME/
echo -e "${GREEN}Fichiers Easy-RSA copiés avec succès.${NC}"

# Initialiser la PKI
echo "Initialisation de la PKI..."
$PKI_HOME/easyrsa init-pki
echo -e "${GREEN}PKI initialisée avec succès.${NC}"

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
echo -e "${GREEN}Variables de configuration écrites avec succès.${NC}"

# Changer les droits d’accès à la fin
echo "Changement des droits d'accès..."
chown -R $PKI_ADMIN_USER:$PKI_ADMIN_USER $PKI_HOME
chmod 600 -R $PKI_HOME
chmod u+x $PKI_HOME/
chmod u+x $PKI_HOME/pki
chmod u+x $PKI_HOME/pki/inline
chmod u+x $PKI_HOME/pki/private
chmod u+x $PKI_HOME/pki/reqs
chmod u+x $PKI_HOME/pki/
chmod u+x $PKI_HOME/easyrsa
chmod 705 $PKI_HOME/x509-types
echo -e "${GREEN}Droits d'accès changés avec succès.${NC}"

# Étapes suivantes en bleu clair
echo -e "\n${LIGHT_BLUE}Script terminé avec succès.${NC}"
echo -e "${LIGHT_BLUE}'su - rootCAadmin' puis exécuter '/home/rootCAadmin/easy-rsa/easyrsa build-ca' afin de créer l'autorité de certification.${NC}"
echo -e "${LIGHT_BLUE}CN: 'Root-CA'${NC}"

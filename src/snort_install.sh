#!/bin/sh

##########################################################################################
#Developped by Projet HEIMDALL : BEDEAU Armand, DUMONT Valentin, GERARD Alex et ZAAR Garry
##########################################################################################

#Variables globales de fonctionnement du script
_date_format=`date +'%B %d %Y %T'`
_ip_addr=`cat ~/snort_src/net_heimdall.conf | grep ip | cut -d '=' -f 2 | cut -d '/' -f 1`
_ip_inet=`cat ~/snort_src/net_heimdall.conf | grep inet | cut -d '=' -f 2`


#Fonction permettant la recuperation automatique des informations reseaux (IP et interface) de la machine
network_config() {
    if [ -f "~/snort_src/net_heimdall.conf" ]; then
        return 0
    else
        #Recuperation de la configuration reseau de la machine IP + eth
        ip_addr=`ip addr | grep -m 1 global | tr -s ' ' ' ' | cut -d ' ' -f 3`
        ip_interface=`ip addr | grep -m 1 global | tr -s ' ' ' ' | cut -d ' ' -f 9`

        mkdir ~/snort_src
        cd ~/snort_src

        touch net_heimdall.conf

        echo "ip=$ip_addr" >> net_heimdall.conf
        echo "inet=$ip_interface" >> net_heimdall.conf
    fi
}


#Fonction permettant d'installer Snort sur la machine
install_snort() {

    echo "Utilisez 'tail -f /var/log/snort_install_log.txt' pour voir la progression de l'installation\n"

    #Creation du fichier de log de l'installation
    sudo touch /var/log/snort_install_log.txt
    sudo chmod 777 /var/log/snort_install_log.txt

    echo "$_date_format : Debut de l'installation de Snort\n\n" >> /var/log/snort_install_log.txt

    echo "Création du dossier d'installation dans ~/snort_src\n"
    echo "\n$_date_format : Création du dossier d'installation dans ~/snort_src\n" >> /var/log/snort_install_log.txt

    #Creation du dossier de preparation d'installation de Snort
    cd ~/snort_src

    echo "Installation des paquets requis ... \n "
    echo "\n$_date_format : Installation des paquets requis\n\n" >> /var/log/snort_install_log.txt

    #Installation des paquets prerequis
    sudo apt-get install -y gcc make libpcre3-dev zlib1g-dev libluajit-5.1-dev libpcap-dev openssl autoconf libtool pkg-config libssl-dev libnghttp2-dev libdumbnet-dev bison flex libdnet >> /var/log/snort_install_log.txt 2>&1

    echo "Telechargement de nghttp2 ... \n "
    echo "\n$_date_format : Telechargement de nghttp2\n\n" >> /var/log/snort_install_log.txt

    #Telechargement de nghttp2
    wget -o /var/log/snort_install_log.txt https://github.com/nghttp2/nghttp2/releases/download/v1.17.0/nghttp2-1.17.0.tar.gz


    echo "Extraction des fichiers de nghttp2 ... \n "
    echo "\n$_date_format : Extraction des fichiers de nghttp2\n\n" >> /var/log/snort_install_log.txt

    #Decompression de l'archive nghttp2
    tar -xzvf nghttp2-1.17.0.tar.gz >> /var/log/snort_install_log.txt 2>&1
    cd nghttp2-1.17.0

    echo "Autoreconf de nghttp2 ... \n "
    echo "\n$_date_format : Autoreconf de nghttp2\n\n" >> /var/log/snort_install_log.txt

    #Autoreconf de nghttp2
    autoreconf -i --force >> /var/log/snort_install_log.txt 2>&1
    automake >> /var/log/snort_install_log.txt 2>&1
    autoconf >> /var/log/snort_install_log.txt 2>&1

    echo "Installation de nghttp2 ... \n "
    echo "\n$_date_format : Installation de nghttp2\n\n" >> /var/log/snort_install_log.txt

    #Installation de nghttp2
    ./configure --enable-lib-only >> /var/log/snort_install_log.txt 2>&1
    make >> /var/log/snort_install_log.txt
    sudo make install >> /var/log/snort_install_log.txt 2>&1

    echo "Telechargement de Daq ...\n"
    echo "\n$_date_format : Telechargement de Daq\n\n" >> /var/log/snort_install_log.txt

    #Telechargement de la source de Daq
    cd ~/snort_src
    wget -o /var/log/snort_install_log.txt https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz

    echo "Extraction des fichiers de Daq ...\n"
    echo "\n$_date_format : Extraction des fichiers de Daq\n\n" >> /var/log/snort_install_log.txt

    #Decompression de l'archive Daqs
    tar -xvzf daq-2.0.6.tar.gz >> /var/log/snort_install_log.txt 2>&1
    cd daq-2.0.6

    echo "Installation et configuration de Daq ...\n"
    echo "\n$_date_format : Installation et configuration de Daq\n\n" >> /var/log/snort_install_log.txt

    #Configuration et installation de Daq
    ./configure >> /var/log/snort_install_log.txt 2>&1 && make >> /var/log/snort_install_log.txt 2>&1 && sudo make install >> /var/log/snort_install_log.txt 2>&1

    echo "Telechargement de Snort ... \n"
    echo "\n$_date_format : Telechargement de Snort\n\n" >> /var/log/snort_install_log.txt

    #Telechargement de la source de Snort
    cd ~/snort_src
    wget -o /var/log/snort_install_log.txt  https://www.snort.org/downloads/snort/snort-2.9.12.tar.gz

    echo "Extraction des fichiers de Snort ...\n"
    echo "\n$_date_format : Telechargement de Snort\n\n" >> /var/log/snort_install_log.txt

    #Decompression de l'archive Snort
    tar -xvzf snort-2.9.12.tar.gz >> /var/log/snort_install_log.txt 2>&1
    cd snort-2.9.12

    echo "Installation de Snort ... \n"
    echo "\n$_date_format : Installation de Snort\n\n" >> /var/log/snort_install_log.txt

    #Configuration et installation de Snort
    ./configure --enable-sourcefire >> /var/log/snort_install_log.txt 2>&1 && make >> /var/log/snort_install_log.txt 2>&1 && sudo make install >> /var/log/snort_install_log.txt 2>&1

    echo "Mise a jour des liens symboliques des libraires partagees ... \n"
    echo "\n$_date_format : Mise a jour des liens symboliques\n\n" >> /var/log/snort_install_log.txt

    #Mise a jour des liens symboliques des librairies partagees
    sudo ldconfig >> /var/log/snort_install_log.txt 2>&1
    sudo ln -s /usr/local/bin/snort /usr/sbin/snort >> /var/log/snort_install_log.txt 2>&1

    echo "Ajout de l'utilisateur et du groupe Snort ... \n"
    echo "\n$_date_format : Ajout de l'utilisateur et du groupe Snort\n\n" >> /var/log/snort_install_log.txt

    #Ajout de l'utilisateur et du groupe Snort
    sudo groupadd snort >> /var/log/snort_install_log.txt 2>&1
    sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort >> /var/log/snort_install_log.txt 2>&1

    echo "Creation des dossiers de configuration de Snort ... \n"
    echo "\n$_date_format : Creation des dossiers de configuration de Snort\n\n" >> /var/log/snort_install_log.txt

    #Creation des dossiers de configuration de Snort
    sudo mkdir -p /etc/snort/rules >> /var/log/snort_install_log.txt 2>&1
    sudo mkdir /var/log/snort >> /var/log/snort_install_log.txt 2>&1
    sudo mkdir /usr/local/lib/snort_dynamicrules >> /var/log/snort_install_log.txt 2>&1

    echo "Modification des droits sur les dossiers de configuration ... \n"
    echo "\n$_date_format : Modification des droits sur les dossiers de configuration\n\n" >> /var/log/snort_install_log.txt

    #Modification des droits sur les dossiers de configuration
    sudo chmod -R 5775 /etc/snort >> /var/log/snort_install_log.txt 2>&1
    sudo chmod -R 5775 /var/log/snort >> /var/log/snort_install_log.txt 2>&1
    sudo chmod -R 5775 /usr/local/lib/snort_dynamicrules >> /var/log/snort_install_log.txt 2>&1
    sudo chown -R snort:snort /etc/snort >> /var/log/snort_install_log.txt 2>&1
    sudo chown -R snort:snort /var/log/snort >> /var/log/snort_install_log.txt 2>&1
    sudo chown -R snort:snort /usr/local/lib/snort_dynamicrules >> /var/log/snort_install_log.txt 2>&1

    echo "Creation des fichiers qui contiendront les règles ... \n"
    echo "\n$_date_format : Creation des fichiers qui contiendront les règles\n\n" >> /var/log/snort_install_log.txt

    #Creation des fichiers des regles
    sudo touch /etc/snort/rules/white_list.rules >> /var/log/snort_install_log.txt 2>&1
    sudo touch /etc/snort/rules/black_list.rules >> /var/log/snort_install_log.txt 2>&1
    sudo touch /etc/snort/rules/local.rules >> /var/log/snort_install_log.txt 2>&1

    echo "Recuperation des fichiers de configuration du dossier de telechargement ... \n"
    echo "\n$_date_format : Recuperation des fichiers de configuration du dossier de telechargement\n\n" >> /var/log/snort_install_log.txt

    #Copie des fichiers de configuration
    sudo cp ~/snort_src/snort-2.9.12/etc/*.conf* /etc/snort >> /var/log/snort_install_log.txt 2>&1
    sudo cp ~/snort_src/snort-2.9.12/etc/*.map /etc/snort >> /var/log/snort_install_log.txt 2>&1

    echo "\n\nResultat : Installation de Snort terminee !\n\n"
    echo "\n$_date_format : Installation de Snort terminee !\n\n" >> /var/log/snort_install_log.txt

    echo "\n\nAppuyer sur n'importe quelle touche pour retourner au menu ..."
    read var

    sudo chmod 755 /var/log/snort_install_log.txt

    menu

}


#Ajout des regles a Snort (Communaute ou Oink Code)
regles_configuration() {

    sudo chmod 777 /var/log/snort_install_log.txt

    echo "Utilisez 'tail -f /var/log/snort_install_log.txt' pour voir la progression de l'installation\n"

    echo "Telechargement des regles de la communaute ...\n"
    echo "\n$_date_format : Telechargement des regles de la communaute\n\n" >> /var/log/snort_install_log.txt

    #Telechargement des regles de la communaute
    wget -o /var/log/snort_install_log.txt https://www.snort.org/rules/community -O ~/community.tar.gz

    echo "Extraction et copie des regles de la communaute ...\n"
    echo "\n$_date_format : Extraction et copie des regles de la communaute\n\n" >> /var/log/snort_install_log.txt

    #Extraction et copie des regles de la communaute
    sudo tar -xvf ~/community.tar.gz -C ~/ >> /var/log/snort_install_log.txt 2>&1
    sudo cp ~/community-rules/* /etc/snort/rules
    sudo sed -i 's/include \$RULE\_PATH/#include \$RULE\_PATH/' /etc/snort/snort.conf

    echo "Configuration des regles de la communaute effectuee !\n"
    echo "\n$_date_format : Configuration des regles de la communaute effectuee !\n\n" >> /var/log/snort_install_log.txt

    sudo chmod 755 /var/log/snort_install_log.txt

    echo "\n\nAppuyer sur n'importe quelle touche pour retourner au menu ..."
    read var

    menu

}


#Modifie la configuration de base de Snort pour utiliser au mieux les regles
includes_configuration() {

    sudo chmod 777 /var/log/snort_install_log.txt

    echo "Utilisez 'tail -f /var/log/snort_install_log.txt' pour voir la progression de l'installation\n"

    echo "Configuration du reseau de Snort ...\n"
    echo "\n$_date_format : Configuration du reseau de Snort\n\n" >> /var/log/snort_install_log.txt

    #Configuration du reseau
    sudo sed -i "s/ipvar HOME_NET any/ipvar HOME_NET "$_ip_addr"\/32/" /etc/snort/snort.conf
    sudo sed -i 's/ipvar EXTERNAL_NET any/ipvar EXTERNAL_NET !$HOME_NET/' /etc/snort/snort.conf
    
    echo "Configuration des dossiers des regles et includes ...\n"
    echo "\n$_date_format : Configuration des dossiers des regles et includes\n\n" >> /var/log/snort_install_log.txt
    #Configuration des dossiers des regles
    sudo sed -i 's/var RULE_PATH ..\/rules/var RULE_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf 
    sudo sed -i 's/var SO_RULE_PATH ..\/so_rules/var SO_RULE_PATH \/etc\/snort\/so_rules/' /etc/snort/snort.conf
    sudo sed -i 's/var PREPROC_RULE_PATH ..\/preproc_rules/var PREPROC_RULE_PATH \/etc\/snort\/preproc_rules/' /etc/snort/snort.conf

    #Configuration des White et Black listes
    sudo sed -i 's/var WHITE_LIST_PATH ..\/rules/var WHITE_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
    sudo sed -i 's/var BLACK_LIST_PATH ..\/rules/var BLACK_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf 

    #Configuration des includes
    sudo sed -i 's/# output unified2: filename merged.log, limit 128, nostamp, mpls_event_types, vlan_event_types/output unified2: filename snort.log, limit 128/' /etc/snort/snort.conf
    sudo sed -i 's/#include $RULE_PATH\/local.rules/include $RULE_PATH\/local.rules/' /etc/snort/snort.conf
    sudo sed -i 's/#include $RULE_PATH\/local.rules/include $RULE_PATH\/local.rules\ninclude $RULE_PATH\/community.rules/' /etc/snort/snort.conf

    echo "Configuration du reseau de Snort et des includes terminee !\n\n"
    echo "\n$_date_format : Configuration du reseau de Snort et des includes terminee !\n\n" >> /var/log/snort_install_log.txt

    sudo chmod 755 /var/log/snort_install_log.txt

    echo "\n\nAppuyer sur n'importe quelle touche pour retourner au menu ..."
    read var

    menu
}


#Fonction permettant la configuration de Snort en tant que service
daemon_snort() {

    sudo chmod 777 /var/log/snort_install_log.txt

    cd ~/snort_src

    echo "Configuration de Snort en tant que daemon ...\n"
    echo "\n$_date_format : Configuration de Snort en tant que daemon\n\n" >> /var/log/snort_install_log.txt

    #Creation du fichier de service
    echo -e "[Unit]\nDescription=Snort NIDS Daemon\nAdter=syslog.target network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i $_ip_inet\n\n[Install]\nWantedBy=multi-user.target" > snort.service
    sudo cp snort.service /lib/systemd/system/snort.service
    
    #Relance du daemon
    sudo systemctl daemon-reload >> /var/log/snort_install_log.txt 2>&1
    sudo systemctl start snort >> /var/log/snort_install_log.txt 2>&1
    sudo systemctl status snort >> /var/log/snort_install_log.txt 2>&1

    echo "Configuration de Snort en tant que daemon terminee !\n\n"
    echo "\n$_date_format : Configuration de Snort en tant que daemon terminee !\n\n" >> /var/log/snort_install_log.txt

    sudo chmod 755 /var/log/snort_install_log.txt

    echo "\n\nAppuyer sur n'importe quelle touche pour retourner au menu ..."
    read var

    menu
}


#Fonction permettant de lancer Snort en mode console
launch_snort() {

    sudo chmod 777 /var/log/snort_install_log.txt

    echo "Lancement de Snort en mode console ... \n\n"
    echo "\n$_date_format : Snort lance en mode console \n\n" >> /var/log/snort_install_log.txt

    sudo chmod 755 /var/log/snort_install_log.txt

    #Lancement de Snort en mode console 
    sudo snort -A console -i "$_ip_inet" -u snort -g snort -c /etc/snort/snort.conf

    echo "\n\nVous venez de quitter la console Snort."
    echo "\n$_date_format : Vous venez de quitter la console Snort !\n\n" >> /var/log/snort_install_log.txt

    sudo chmod 755 /var/log/snort_install_log.txt

    echo "\n\nAppuyer sur n'importe quelle touche pour retourner au menu ..."
    read var

    menu
}


#Fonction permettant de configurer manuellement la configuration reseau de Snort
modify_network() {

    sudo chmod 777 /var/log/snort_install_log.txt

    echo "Modification du reseau pour snort ... \n\n"
    echo "\n$_date_format : Modification du reseau pour snort \n\n" >> /var/log/snort_install_log.txt

    #Nouvelle adresse IP
    echo "\nEntrez la nouvelle adresse IP avec son masque (ex: 192.168.1.1/24) : "
    read ip_given

    #Nouvelle interface
    echo "\nEntrez la nouvelle interface (ex: eth0) : "
    read inet_given

    #Modification dans le fichier reseau de l'installateur
    echo "ip=$ip_given" > ~/snort_src/net_heimdall.conf
    echo "inet=$inet_given" >> ~/snort_src/net_heimdall.conf

    echo "IP=$ip_given et INET=$inet_given\n\n"
    echo "\n$_date_format : IP=$ip_given et INET=$inet_given \n\n" >> /var/log/snort_install_log.txt

    echo "Modification du reseau terminee !\n\n"
    echo "\n$_date_format : Modification du reseau terminee !\n\n" >> /var/log/snort_install_log.txt

    sudo chmod 755 /var/log/snort_install_log.txt

    echo "\n\nAppuyer sur n'importe quelle touche pour retourner au menu ..."
    read var

    menu    
}


#Fonction affichant le menu a l'utilisateur
menu_affichage() {

    echo "0 - Modifier les parametres reseaux pour Snort (Interface, adresse IP), par defaut ce script recupere l'adresse de la premiere interface donnee par ip addr" 
    echo "1 - Installation de Snort"
    echo "2 - Installation des regles (communauté, oink code [non implemente], ..)"
    echo "3 - Configuration du réseau de Snort"
    echo "4 - Verifier la configuration essentielle de Snort"
    echo "5 - Configuration de Snort en tant que daemon"
    echo "6 - Lancer Snort en console"
    echo "9 - Quitter"
    echo "Votre choix : "
}


#Fonction gerant les erreurs possibles
erreur_affichage() {

    case $1 in
        "install_not_found")
            echo "Snort semble etre deja installe. Merci de verifier dans /etc/snort\n"
            ;;
        "rules_not_found")
            echo "Les regles de base de Snort ne semblent pas etre configurees dans /etc/snort/rules\n"
            ;;
        *)
            echo "Une erreur generale est survenue\n"
            ;;
    esac
        
}


#Fonction de menu principal
menu() {

    choice=10

    clear

    echo "
__________                   __        __        ___  ___         .__             .___      .__  .__   
\______   \_______  ____    |__| _____/  |_     /   |_|   \   ____ |__| _____    __| _/____  |  | |  |  
 |     ___/\_  __ \/  _ \   |  |/ __ \   __\   /           \_/ __ \|  |/     \  / __ |\__  \ |  | |  |  
 |    |     |  | \(  <_> )  |  \  ___/|  |     \    ___    /\  ___/|  |  Y Y  \/ /_/ | / __ \|  |_|  |__
 |____|     |__|   \____/\__|  |\___  >__|      \___| |___/  \___  >__|__|_|  /\____ |(____  /____/____/
                        \______|    \/                  \/       \/         \/      \/     \/           
"

    echo "Bienvenue dans l'installation, la configuration et le lancement de Snort\n\n"

    while [ $choice -ne 9 ]; do

        menu_affichage
        read choice

        case $choice in
            0)
                modify_network
                ;;
            1)
                if [ -d "/etc/snort" ]; then
                    erreur_affichage install_not_found
                else
                    install_snort
                fi
                ;;
            2)
                if [ -d "/etc/snort" ]; then
                    regles_configuration
                else
                    erreur_affichage install_not_found
                fi
                ;;
            3)
                if [ -d "/etc/snort/rules" ]; then
                    includes_configuration
                else
                    erreur_affichage rules_not_found
                fi
                ;;
            4)
                if [ -d "/etc/snort/rules" ]; then
                    sudo snort -T -c /etc/snort/snort.conf
                    echo "\n\nAppuyer sur n'importe quelle touche pour retourner au menu ..."
                    read var
                else
                    erreur_affichage rules_not_found
                fi
                ;;
            5)
                if [ -d "/etc/snort/rules" ]; then
                    daemon_snort
                else
                    erreur_affichage rules_not_found
                fi
                ;;
            6)
                if [ -d "/etc/snort/rules" ]; then
                    launch_snort
                else
                    erreur_affichage rules_not_found
                fi
                ;;
            9)
                echo "Vous quittez le programme d'installation et de configuration de Snort \n"
                exit 0
                ;;
            *)
                echo "Mauvais choix merci de choisir parmi le menu suivant : \n"
                ;;
        esac
    done
}

network_config
menu
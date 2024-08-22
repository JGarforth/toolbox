import network_functions
import web_app_functions


def initialize_interface():
    print("""
******************************************
*********** WELCOME TO TOOLBOX ***********
******************************************""")

    print("""
First, choose your target
1. Network
2. Web Application
3. Hash Cracker
4. Exit""")

    user_input = input(">")

    match user_input:
        case '1':
            network_menu()
        case '2':
            web_app_menu()
        case '3':
            return
        case '4':
            print("Goodbye.")
            return
        case _:
            print("Invalid input.")
            initialize_interface()


def network_menu():
    print("""
**** Welcome to Network Cracker ****
1. Passive Scan (TCPDump)
2. Subnet Scan
3. Port Scan
4. SSH Bruteforce
5. FTP Bruteforce
6. Go back""")

    user_input = input(">")

    match user_input:
        case '1':
            duration = input("For how many seconds should packet capture be active? >")
            network_functions.packet_capture(duration)
            input("Press any button to continue.")
            network_menu()
        case '2':
            target_subnet = input("What subnet is being scanned? >")
            network_functions.subnet_scan(target_subnet)
            input("Press any button to continue.")
            network_menu()
        case '3':
            target_ip = input("What is the target IP? >")
            print("""
                Select scan Intensity:
                1. Vulnerable Ports (Fastest)
                2. Moderate (Well-Known Ports)
                3. Intensive (All Ports. WARNING: SLOW)""")
            intensity_input = input(">")

            if intensity_input == '1':
                intensity = 'vulnerable'
            elif intensity_input == '2':
                intensity = 'moderate'
            elif intensity_input == '3':
                intensity = 'intensive'
            else:
                print("Invalid input.")
                return network_menu()

            network_functions.port_scan(target_ip, intensity)
            input("Press any button to continue.")
            network_menu()
        case '4':
            target_ip = input("What is the target IP? >")
            password_list, list_type = select_password_list()
            if list_type == 'FULL':
                network_functions.ssh_bruteforce_full(target_ip, password_list)
            else:
                username = input("What is the SSH username? >")
                network_functions.ssh_bruteforce(target_ip, username, password_list)
            input("Press any button to continue.")
            network_menu()
        case '5':
            target_ip = input("What is the target IP? >")
            password_list, list_type = select_password_list()
            if list_type == 'FULL':
                network_functions.ftp_bruteforce_full(target_ip, password_list)
            else:
                username = input("What is the FTP username? >")
                network_functions.ftp_bruteforce(target_ip, username, password_list)
            input("Press any button to continue.")
            network_menu()
        case '6':
            initialize_interface()
        case _:
            print("Invalid input.")
            network_menu()


def web_app_menu():
    print("""
**** Welcome to Web App Cracker ****
1. DNS Enumeration
2. SQL Injection Test
3. XSS Test
4. CSRF
5. Automate Common Exploits
6. Go back""")

    user_input = input(">")

    target_url = input("Enter the target URL >")

    match user_input:
        case '1':
            input("Press any button to continue.")
            web_app_menu()
        case '2':
            web_app_functions.sql_injection(target_url)
            input("Press any button to continue.")
            web_app_menu()
        case '3':
            web_app_functions.xss(target_url)
            input("Press any button to continue.")
            web_app_menu()
        case '4':
            web_app_functions.csrf(target_url)
            input("Press any button to continue.")
            web_app_menu()
        case '5':
            web_app_functions.automate_all(target_url)
            input("Press any button to continue.")
            web_app_menu()
        case '6':
            initialize_interface()
        case _:
            print("Invalid input.")
            web_app_menu()


def select_password_list():
    print("""
**** Select Password List ****
1. top_12_thousand.txt
2. top_100_thousand.txt
3. ssh_credentials.txt (for SSH)
4. ftp_credentials.txt (for FTP)
5. Use your own list
6. Go back""")

    user_input = input(">")

    match user_input:
        case '1':
            return 'top_12_thousand.txt', None
        case '2':
            return 'top_100_thousand.txt', None
        case '3':
            return 'ssh_credentials.txt', 'FULL'
        case '4':
            return 'ftp_credentials.txt', 'FULL'
        case '5':
            custom_list = input("Enter the path to your password list: ")
            return custom_list, None
        case '6':
            return None, None
        case _:
            print("Invalid input.")
            return select_password_list()


if __name__ == '__main__':
    initialize_interface()

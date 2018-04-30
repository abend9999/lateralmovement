# Lateral Movement

https://attack.mitre.org/wiki/Lateral_Movement でLateral Movementの手法に関して記載されたものを翻訳しました。

## Tactic Description

Lateral movement consists of techniques that enable an adversary to access and control remote systems on a network and could, but does not necessarily, include execution of tools on remote systems. The lateral movement techniques could allow an adversary to gather information from a system without needing additional tools, such as a remote access tool.

横展開は攻撃者がネットワークやクラウド上のリモートシステムにアクセスし制御を可能にする技術から成り立っており、必要ではないがリモートシステムでツールの実行を含むことができます。横展開の技術により攻撃者はリモートアクセスツールなどの追加のツールを必要とせずにシステムから情報収集することができます。

An adversary can use lateral movement for many purposes, including remote Execution of tools, pivoting to additional systems, access to specific information or files, access to additional credentials, or to cause an effect. The ability to remotely execute scripts or code can be a feature of adversary remote access tools, but adversaries may also reduce their tool footprint on the network by using legitimate credentials alongside inherent network and operating system functionality to remotely connect to systems.

攻撃者はツールのリモート実行、追加システムへのピボット、特定の情報またはファイルへのアクセス、追加の資格情報へのアクセスまたは効果を引き起こすなど、様々な目的のために横展開を悪用します。攻撃者のツールへリモートからアクセスさせるための機能としてリモートからスクリプトやコードを実行させますが、攻撃者はリモートからシステムに接続するために内在するネットワークやOSの機能とともにネットワーク上で正当な資格情報を使用してツールのフットプリントを減らします。

Movement across a network from one system to another may be necessary to achieve an adversary’s goals. Thus lateral movement, and the techniques that lateral movement relies on, are often very important to an adversary's set of capabilities and part of a broader set of information and access dependencies that the adversary takes advantage of within a network. To understand intrinsic security dependencies, it is important to know the relationships between accounts and access privileges across all systems on a network. Lateral movement may not always be a requirement for an adversary. If an adversary can reach the goal with access to the initial system, then additional movement throughout a network may be unnecessary.

あるシステムから別のシステムへのネットワーク移動が攻撃者の目標を達成するために必要となる場合があります。したがって、横展開や横展開に頼る手法は、攻撃者がネットワーク内で利用する攻撃者の能力セットや情報とアクセスの依存関係の幅広いセットの一部が非常に重要となります。本質的なセキュリティの依存関係を理解するために、ネットワーク上のすべてのシステムでアカウントとアクセス権限の関係を把握することが重要です。横展開は攻撃者にとって常に求められることではないです。もし攻撃者が最初のシステムにアクセスして目標を達成できたら、ネットワーク全体への追加の移動は不要になります。


###Technique
#####AppleScript

macOS and OS X applications send AppleEvent messages to each other for interprocess communications (IPC). These messages can be easily scripted with AppleScript for local or remote IPC. Osascript executes AppleScript and any other Open Scripting Architecture (OSA) language scripts. A list of OSA languages installed on a system can be found by using the osalang program.
AppleEvent messages can be sent independently or as part of a script. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely.

Adversaries can use this to interact with open SSH connection, move to remote machines, and even present users with fake dialog boxes. These events cannot start applications remotely (they can start them locally though), but can interact with applications if they're already running remotely. Since this is a scripting language, it can be used to launch more common techniques as well such as a reverse shell via python. Scripts can be run from the command lie via osascript /path/to/script or osascript -e "script here".

macOSやOS Xのアプリケーションはプロセス間通信(IPC)を行うために、AppleEventメッセージを相互に送信する。これらのメッセージはローカルまたはリモートのIPCのためにAppleScriptで容易にスクリプト化できます。OsascriptはAppleScriptやその他のOpen Scripting Architecture(OSA)言語スクリプトで実行されます。システムにインストールされているOSA言語のリストは、OSA言語のプログラムで見つけることができます。
AppleEventメッセージは独立して送信することやスクリプトの一部として送信することもできます。これらのイベントは開いているウィンドウの検索、キーストロークの送信、ローカルまたはリモートでほとんどのオープンなアプリケーションと通信することができます。

攻撃者はオープンになっているSSHコネクションを利用して、リモートのPCに侵入したり偽のダイアログボックスを表示させたりできます。これらのイベントはリモートからアプリケーションを開始することはできません(ローカルでは開始することができます)。ですが、リモートで既に動いているアプリケーションとは通信が可能です。スクリプト言語であるため、python2経由でリバースシェルのように一般的な手法で起動することもできます。スクリプトは「osascript /path/to/script」や「osascript -e "script here"」のように実行可能です。


#####Application Deployment Software

Adversaries may deploy malicious software to systems within a network using application deployment systems employed by enterprise administrators. The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the deployment server, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform software deployment. Access to a network-wide or enterprise-wide software deployment system enables an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.

攻撃者は企業の管理者が使用するデプロイされたアプリケーションを利用してネットワーク内のシステムに不正なソフトウェアを展開することができます。デプロイするための権限はシステム構成によって異なります。デプロイするサーバに直接アクセスできる場合はローカルの資格情報で十分な場合や特定のドメインの資格情報が必要な場合があります。ただ、管理者権限を持つアカウントでのログインやデプロイを行うことを求められる場合があります。ネットワーク規模または企業規模のデプロイされたアプリケーションにアクセスすることで攻撃者はリモートから接続されたすべてのシステムでコードを実行できます。システムへの横展開に利用されたり、情報収集やすべてのエンドポイントのハードディスクから情報の消去などの被害を受けます。


#####Distributed Component Object Model

Windows Distributed Component Object Model (DCOM) is transparent middleware that extends the functionality of Component Object Model (COM) beyond a local computer using remote procedure call (RPC) technology. COM is a component of the Windows application programming interface (API) that enables interaction between software objects. Through COM, a client object can call methods of server objects, which are typically Dynamic Link Libraries (DLL) or executables (EXE).
Permissions to interact with local and remote server COM objects are specified by access control lists (ACL) in the Registry. By default, only Administrators may remotely activate and launch COM objects through DCOM.

Adversaries may use DCOM for lateral movement. Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications as well as other Windows objects that contain insecure methods. DCOM can also execute macros in existing documents and may also invoke Dynamic Data Exchange (DDE) execution directly through a COM created instance of a Microsoft Office application, bypassing the need for a malicious document.

Windows Distributed Component Object Model (DCOM)はRPCを用いてローカル環境からCOMの機能を拡張する透過的なミドルウェアです。COMはソフトウエア間通信が可能なWindows APIのコンポーネントです。COMを介してクライアントオブジェクトは一般的にDLLやEXEであるサーバオブジェクトのメソッドを呼び出すことができます。
ローカルやリモートのサーバとのCOMオブジェクトとの通信権限はレジストリのACLによって詳細設定されています。デフォルトで管理者のみがリモートからDCOMを介してCOMオブジェクトを有効化し実行できます。

攻撃者は横展開にDCOMを利用します。DCOMを介して攻撃者は適切な特権ユーザのコンテキストの中で行動し、安全ではない方法を含む他のWindowsオブジェクトと同様にOfficeアプリケーションを通じて、リモートから任意のシェルコードを直接実行されます。DCOMは既存のドキュメントでマクロを実行でき、悪意のあるドキュメントの必要性はなくCOMを介して作成されたMicrosoftOfficeアプリケーションのインスタンスを直接実行できるDDEを起動できます。


#####Exploitation of Remote Services

Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.
An adversary may need to determine if the remote system is in a vulnerable state, which may be done through Network Service Scanning or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities, or security software that may be used to detect or contain remote exploitation. Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources.

There are several well-known vulnerabilities that exist in common services such as SMB and RDP as well as applications that may be used within internal networks such as MySQL and web server services.

Depending on the permissions level of the vulnerable remote service an adversary may achieve Exploitation for Privilege Escalation as a result of lateral movement exploitation as well.

ソフトウエアの脆弱性の悪用により攻撃者は悪意のあるコードを実行するためにプログラムやサービス、OSのソフトウェアまたはカーネル自体のプログラミングエラーを活用します。リモートサービスの情報漏洩させる一般的な目的は、リモートシステムへのアクセスを可能にするために横展開することにあります。
攻撃者はリモートシステムが脆弱な状態かどうか判断する必要があります。ネットワークサービススキャンや他の一般的な探索手法と通して実施したり、ネットワークに展開された脆弱なソフトウェアや脆弱性のパッチの欠如、脆弱性、リモートの攻撃の検知や包含されたセキュリティソフトウェアです。サーバは横展開による搾取のために価値の高いターゲットである可能性が高いですが、エンドポイントシステムは利点や追加のリソースへのアクセスを提供する場合に危険にさらされる可能性があります。

MySQLやWebサーバサービスのような内部ネットワーク内で利用されるアプリケーションと同様にSMBやRDPなどの一般的なサービスに存在するいくつかの既知の脆弱性があります。

脆弱なリモートサービスの権限レベルに応じて、攻撃者は横展開の搾取の結果として権限昇格を達成する可能性があります。


#####Logon Scripts

===Windows===
Windows allows logon scripts to be run whenever a specific user or group of users log into a system. The scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server.

If adversaries can access these scripts, they may insert additional code into the logon script to execute their tools when a user logs in. This code can allow them to maintain persistence on a single system, if it is a local script, or to move laterally within a network, if the script is stored on a central server and pushed to many systems. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

Mac
Mac allows login and logoff hooks to be run as root whenever a specific user logs into or out of a system. A login hook tells Mac OS X to execute a certain script when a user logs in, but unlike startup items, a login hook executes as root. There can only be one login hook at a time though. If adversaries can access these scripts, they can insert additional code to the script to execute their tools when a user logs in.

Windowsでは、特定のユーザやグループがログインする際にログオンスクリプトの実行を設定できます。スクリプトを使用して管理機能を実行することができます。管理機能は他のプログラムを実行したり、内部ログサーバに情報を送信することができます。
攻撃者がこれらのスクリプトにアクセスできた場合に、攻撃者が攻撃者のツールを実行させるためのコードをログオンスクリプトに追加する可能性があります。追加されたコードがローカルスクリプトの場合、システム上での継続的な維持に悪用され、スクリプトが中心的なサーバへの格納や多数システムへの攻撃に利用されたもの場合、ネットワーク内の横展開に悪用されます。ログオンスクリプトのアクセス設定にもよるが、ローカルの資格情報または管理者アカウントが必要になります。

Macでは特定のユーザのログイン、ログオフをフックすることは可能です。Mac OS Xではログインをフックし、ユーザがログインするときにスクリプトを実行することができます。ただし、1回のログインにつき1回しかフックされません。攻撃者がスクリプトにアクセスできた場合、ユーザがログインするときに攻撃者のツールを実行させるスクリプトを追加することができます。


#####Pass the Hash

Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems. Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.

Pass the Hashはユーザの平文のパスワードを用いずにユーザとして認証する方法です。この方法は平文のパスワードを要求される通常の認証を迂回し、パスワードのハッシュで認証部分に直接移行します。この手法では利用されている正しいパスワードハッシュを資格情報へアクセスする手法を用いてキャプチャされます。一度認証されてしまうとPass the Hashはローカルまたはリモートのシステムで操作することができます。Windows7およびKB2871997以降では正当なドメインユーザかRIDが500であるAdministratorアカウントが求められます。

#####Pass the Tichket

Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.
In this technique, valid Kerberos tickets for Valid Accounts are captured by Credential Dumping. A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access.

Silver Tickets can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint).

Golden Tickets can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory.

Pass the Ticketはアカウントのパスワードを用いずにKerberosチケットでシステムへの認証を行う方法です。Kerberos認証はリモートシステムへの横展開するため、最初に使用されます。
この手法は有効なアカウントのKerberosチケットを資格情報をダンプしたものを取得します。ユーザのサービスチケットやチケット許可チケット(TGT)はアクセスレベルによって取得できます。サービスチケットは特定のリソースへのアクセスを許可しますが、TGTはTicket Granting Service (TGS) からサービスチケットを要求し、ユーザの権限でアクセス可能なすべてのリソースにアクセス可能です。

Sliverチケットは認証メカニズムとしてKerberosを用いたサービスを取得したり、特定のリソースやリソースを提供するシステム(たとえばSharePoint)にアクセス可能なチケットを生成することができます。

Goldenチケットはキー配布サービスアカウントであるKRBTGTのNTLMハッシュを用いて取得でき、Active Directory内の任意のユーザのTGTを生成可能です。


#####Remote Desktop Protocol

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). There are other implementations and third-party tools that provide graphical access Remote Services similar to RDS.
Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the Accessibility Features technique for Persistence.

Adversaries may also perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session and prompted with a question. With System permissions and using Terminal Services Console, c:\windows\system32\tscon.exe [session number to be stolen], an adversary can hijack a session without the need for credentials or prompts to the user. This can be done remotely or locally and with active or disconnected sessions. It can also lead to Remote System Discovery and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in RedSnarf.


リモートデスクトップはOSの一般的な機能です。この機能によりリモートシステムにGUIを用いて対話型セッションにログインできます。マイクロソフトではRemote Desktop Services (RDS)として、Remote Desktop Protocol (RDP)の実装しています。RDSに類似したリモートサービスへのグラフィカルアクセスを提供する他の実装やサードパーティーのツールもあります。
攻撃者はサービスが有効であったり、既知の資格情報をもつアカウントでアクセスできる場合にRDP/RDSを介してリモートシステムへのアクセスできる範囲を拡大することができます。攻撃者は資格情報を取得するためにRDPを用いて資格情報へアクセスする可能性が高いです。また、攻撃者は持続性のためにユーザ補助機能と連携してRDPを利用します。

攻撃者は正当な利用者のリモートセッションを盗むことを伴うRDPセッションハイジャックを実行することもできます。一般的に第三者のセッションを盗もうとしている場合に利用者に通知され、プロンプトによる確認が行われます。システム権限があり、ターミナルサービスのコンソールが用いて、c:\windows\system32\tscon.exe [盗むセッション番号]で、攻撃者は資格情報やプロンプトを必要とせずにセッションを乗っ取ることができます。これはリモートまたはローカルや有効または切断されたセッションで実行できます。また、ドメイン管理者以上の権限をもつアカウントのセッションを盗むことでリモートからのシステム検出や権限昇格につながる可能性があります。Windowsコマンドによりすべて実行することができますが、RedSnarfの機能として追加されています。


#####Remote File Copy

Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp. Adversaries may also copy files laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with Windows Admin Shares or Remote Desktop Protocol.

ファイルをあるシステムから別のシステムにコピーして、操作の過程で攻撃ツールやほかのファイルを保存することができます。FTPなどの別のツールを用いて代替プロトコルを介して被害者のネットワークにツールを持ち込むためにファイルを外部の攻撃者が管理するシステムからC&Cのチャネルを介してコピーされます。ファイルはMacやLinuxに元々あるscp、rsyncやsftpのようなツールを介してコピーされます。攻撃者は内部の被害者であるシステム間で横展開をサポートするためにリモート実行で接続されたネットワークにSMBを介してのファイル共有やWindows管理共有やRDPを用いた認証された接続を用いてファイルをコピーをします。


#####Remote Services

An adversary may use Valid Accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.

攻撃者はtelnet、ssh、VNCなどのリモート接続を許可するように特別に設計されたサービスにログインするために、有効なアカウントを使用する。攻撃者はログオンしたユーザとして行動することができてしまいます。


#####Replication Through Removable Media

Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.

攻撃者はメディアが別システムに挿入されたときや実行されたときにマルウェアのリムバーブルメディアへのコピーや自動実行機能による実行により切断または隔離されたネットワークへ侵入できる可能性があります。これは、リムバーブルメディアに保存されている実行ファイルの変更やマルウェアをコピーして利用者を欺くために正当なファイルのように名前を変更し分離されたシステムでの実行により起きます。


#####SSH Hijacking

Secure Shell (SSH) is a standard means of remote access on Linux and Mac systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair.
In order to move laterally from a compromised host, adversaries may take advantage of trust relationships established with other systems via public key authentication in active SSH sessions by hijacking an existing connection to another system. This may occur through compromising the SSH agent itself or by having access to the agent's socket. If an adversary is able to obtain root access, then hijacking SSH sessions is likely trivial. Compromising the SSH agent also provides access to intercept SSH credentials.

SSH Hijacking differs from use of Remote Services because it injects into an existing SSH session rather than creating a new session using Valid Accounts.

Secure Shell(SSH)はLinuxやMacでリモートからアクセスする標準的な手段です。SSHによりユーザは暗号化されたトンネルを介して別のシステムに接続することができ、一般的にパスワード認証、証明書、非対称暗号鍵で認証されます。侵入済みのホストから横展開するために攻撃者は、他のシステムへの既存接続をハイジャックし有効なSSHセッションで公開鍵認証を介した他のシステムと確立された信頼関係を利用することができます。これはSSHエージェント自体を侵害するか、エージェントのソケットにアクセスすることにより発生する可能性があります。攻撃者がrootでのアクセスができた場合に、SSHセッションをハイジャックすることは簡単にできてしまいます。SSHエージェントの危殆化によりSSHの資格情報を傍受するためのアクセスもできます。SSHハイジャックは有効なアカウントでの新しいセッションを作成するのではなく、既存のSSHセッションに挿入するためリモートサービスの利用と異なります。


#####Shared Webroot

Adversaries may add malicious content to an internally accessible website through an open network file share that contains the website's webroot or Web content directory and then browse to that content with a Web browser to cause the server to execute the malicious content. The malicious content will typically run under the context and permissions of the Web server process, often resulting in local system or administrative privileges, depending on how the Web server is configured. This mechanism of shared access and remote execution could be used for lateral movement to the system running the Web server. For example, a Web server running PHP with an open network share could allow an adversary to upload a remote access tool and PHP script to execute the RAT on the system running the Web server when a specific page is visited.

攻撃者はWebサイトのWebルートまたはWebコンテンツディレクトリを含むオープンなネットワーク共有を介して内部アクセス可能なWebサイトへ悪意のあるコンテンツを追加できます。そして、Webブラウザによって悪意あるコンテンツへアクセスすることでサーバにより実行させられてしまいます。悪意あるコンテンツは通常、Webサーバのプロセスのコンテキストと権限下で実行され、ローカルシステム権限または管理者権限で結果的に発生したり、Webサーバの設定に依存します。共有アクセスやリモート実行の方法はWebサーバが稼働するシステムへの横展開に利用することができます。例えば、オープンネットワークで共有されているPHPが稼働するWebサーバは、リモートアクセスツールやPHPスクリプトのアップロードや特定ページへのアクセス時にWebサーバを実行しているシステム上でRATを実行させられたりします。


#####Taint Shared Content

Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally. A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory. It uses Shortcut Modification of directory .LNK files that use Masquerading to look like the real directories, which are hidden through Hidden Files and Directories. The malicious .LNK-based directories have an embedded command that executes the hidden malware file in the directory and then opens the real intended directory so that the user's expected action still occurs. When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts.

ネットワークドライブや別の共有場所に保存されたコンテンツは悪意のあるプログラムやスクリプト、攻撃コードを別の正当なファイルに追加することで汚染される可能性があります。ユーザが汚染されたコンテンツを開くと、悪意のある部分によりリモートシステム上で攻撃者のコードが実行さます。攻撃者は横展開するために共有されたコンテンツを汚染する可能性があります。ディレクトリ共有ピボットは共有されたネットワークディレクトリへユーザがアクセスするときにマルウェアを伝染させるためにいくつかある他の手法の1つです。隠しファイルやディレクトを通して隠された実際のディレクトリのように見せかけるディレクトリ .LNKファイルのショートカットを変更します。悪意のある.LNKベースのディレクトリはディレクトリ内の隠されたマルウェアを実行させたり、ユーザの予想される動作が行われるために実際の意図したディレクトリを開かせる埋め込まれたコマンドがあります。頻繁にネットワークディレクトリを利用すると、頻繁な再感染やシステムや潜在的に新規アカウントや高権限のアカウントへの広範囲なアクセスが発生する可能性があります。


#####Third-party Software

Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.). If an adversary gains access to these systems, then they may be able to execute code.
Adversaries may gain access to and use third-party application deployment systems installed within an enterprise network. Access to a network-wide or enterprise-wide software deployment system enables an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.

The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the deployment server, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform software deployment.

サードバーティー製のアプリケーションやソフトウェアを展開するためのシステムは、管理目的でネットワーク環境で利用されている可能性があります(SCCM、VNC、HBSS、Altirisなど)。攻撃者はこれらのシステムへアクセスできた場合、コードを実行できる可能性があります。攻撃者は企業のネットワーク内にインストールされたサードパーティー製のアプリケーションを展開するためのシステムにアクセスし、悪用する可能性があります。ネットワーク規模または企業規模でソフトウェアを展開するシステムへのアクセスにより、攻撃者はそのようなシステムに接続しているすべてのシステムでリモートからコード実行できます。このアクセスにより横展開に悪用されたり、情報収集やすべてのエンドポイントでのハードドライプから情報を削除するなどの特定の被害を引き起こされる可能性があります。この操作に必要な権限はシステムによってことなります。展開するためのサーバへ直接アクセスすることでローカルの資格情報で十分な場合や特定ドメインの資格情報が必要な場合があります。ただ、システムへのログインやソフトウェアの展開を行うために管理者アカウントが必要な場合があります。

#####Windows Admin Shares

Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include C$, ADMIN$, and IPC$.
Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over server message block (SMB) to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are Scheduled Task, Service Execution, and Windows Management Instrumentation. Adversaries can also use NTLM hashes to access administrator shares on systems with Pass the Hash and certain configuration and patch levels.

The Net utility can be used to connect to Windows admin shares on remote systems using net use commands with valid credentials.

Windowsシステムには管理者のみがアクセス可能な隠れたネットワーク共有があり、リモートからファイルコピーや他の管理機能を提供します。C$、ADMIN$、IPC$を含むネットワーク共有があります。攻撃者RPCでシステムとの対話やファイル転送、リモートから転送されたバイナリの実行するためにSMBでリモートからアクセスできる管理者レベルの有効なアカウントと組み合わせて悪用します。SMB/RPC上の認証されたセッションに依存する実行手法の例として、スケジュールされたタスク、サービス実行やWindows Management Instrumentationがあります。攻撃者はシステム上の管理者の共有にアクセスするためにPass the Hashや特定の構成、パッチレベルででNTLMハッシュを利用することもできます。netユーティリティは有効な資格情報でのnet useコマンドによりリモートシステム上のWindows管理者共有に接続するために利用することができます。

#####Windows Remote Management

Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). It may be called with the winrm command or by any number of programs such as PowerShell.

Windows Remote Management (WinRM)は、ユーザーがリモートのシステムとやりとりできる（実行可能ファイルの実行、レジストリの変更、サービスの変更など）、Windowsサービスやプロトコルの名前です。WinRMはwinrmコマンドまたはPowerShellで任意の数のプログラムで呼び出すことができます。


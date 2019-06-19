
### install dependency 

```shell
sudo apt-get install build-essential patch ruby-dev zlib1g-dev liblzma-dev
sudo gem install nokogiri

sudo apt-get install postgresql-common
sudo apt-get install postgresql libpq-dev
sudo gem install pg -v '0.21.0' --source 'https://rubygems.org/'

sudo apt-get install libpcap-dev
sudo gem install pcaprub -v '0.13.0' --source 'https://rubygems.org/'

sudo apt-get install libsqlite3-dev
sudo gem install pcaprub -v '0.13.0' --source 'https://rubygems.org/'

wget https://github.com/rapid7/metasploit-framework/archive/master.zip
cd sploit/metasploit-framework-master/
bundle install

```

### Raw

```
------------------------------------------------


metasploit install

curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall

https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers


ubuntu@ubuntu:~/smash$ curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
>   chmod 755 msfinstall && \
>   ./msfinstall
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  5532  100  5532    0     0  25730      0 --:--:-- --:--:-- --:--:-- 25730
Switching to root user to update the package
Adding metasploit-framework to your repository list..OK
Updating package cache..OK
Checking for and installing update..
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following NEW packages will be installed:
  metasploit-framework
0 upgraded, 1 newly installed, 0 to remove and 130 not upgraded.
Need to get 212 MB of archives.
After this operation, 476 MB of additional disk space will be used.
Get:1 http://downloads.metasploit.com/data/releases/metasploit-framework/apt lucid/main amd64 metasploit-framework amd64 5.0.30+20190614201450~1rapid7-1 [212 MB]
Fetched 212 MB in 18s (11.6 MB/s)                                                                                                                                    
Selecting previously unselected package metasploit-framework.
(Reading database ... 72344 files and directories currently installed.)
Preparing to unpack .../metasploit-framework_5.0.30+20190614201450~1rapid7-1_amd64.deb ...
Unpacking metasploit-framework (5.0.30+20190614201450~1rapid7-1) ...
Setting up metasploit-framework (5.0.30+20190614201450~1rapid7-1) ...
update-alternatives: using /opt/metasploit-framework/bin/msfbinscan to provide /usr/bin/msfbinscan (msfbinscan) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfconsole to provide /usr/bin/msfconsole (msfconsole) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfd to provide /usr/bin/msfd (msfd) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfdb to provide /usr/bin/msfdb (msfdb) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfelfscan to provide /usr/bin/msfelfscan (msfelfscan) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfmachscan to provide /usr/bin/msfmachscan (msfmachscan) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfpescan to provide /usr/bin/msfpescan (msfpescan) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfrop to provide /usr/bin/msfrop (msfrop) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfrpc to provide /usr/bin/msfrpc (msfrpc) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfrpcd to provide /usr/bin/msfrpcd (msfrpcd) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfupdate to provide /usr/bin/msfupdate (msfupdate) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfvenom to provide /usr/bin/msfvenom (msfvenom) in auto mode
Run msfconsole to get started
ubuntu@ubuntu:~/smash$ 


wget https://github.com/rapid7/metasploit-framework/archive/master.zip
sudo apt install unzip

/home/ubuntu/sploit/metasploit-framework-master/tools/exploit

sudo apt install ruby

$ apt list --installed | grep meta

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

metasploit-framework/unknown,now 5.0.30+20190614201450~1rapid7-1 amd64 [installed]

$ dpkg --list | grep meta
ii  init                                  1.51                              amd64        metapackage ensuring an init system is installed
ii  metasploit-framework                  5.0.30+20190614201450~1rapid7-1   amd64        The full stack of metasploit-framework

https://apt.metasploit.com/
https://apt.metasploit.com/pool/main/m/metasploit-framework/metasploit-framework_5.0.30%2B20190614201450~1rapid7-1_amd64.deb

wget https://apt.metasploit.com/pool/main/m/metasploit-framework/metasploit-framework_5.0.30%2B20190614201450~1rapid7-1_amd64.deb

ubuntu@ubuntu:~/sploit$ dpkg --info metasploit-framework_5.0.30+20190614201450~1rapid7-1_amd64.deb 
 new Debian package, version 2.0.
 size 212468654 bytes: control archive=851525 bytes.
     342 bytes,    11 lines      control              
 4002686 bytes, 31097 lines      md5sums              
     525 bytes,    18 lines   *  postinst             #!/bin/sh
      99 bytes,     7 lines   *  postrm               #!/bin/sh
      89 bytes,     6 lines   *  preinst              #!/bin/sh
     361 bytes,    15 lines   *  prerm                #!/bin/sh
 Package: metasploit-framework
 Version: 5.0.30+20190614201450~1rapid7-1
 License: Unspecified
 Vendor: Omnibus <omnibus@getchef.com>
 Architecture: amd64
 Maintainer: Rapid7 Release Engineering <r7_re@rapid7.com>
 Installed-Size: 464819
 Section: misc
 Priority: extra
 Homepage: https://rapid7.com
 Description: The full stack of metasploit-framework

 $ dpkg-query -L metasploit-framework | grep pattern_create
/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb

https://askubuntu.com/questions/32507/how-do-i-get-a-list-of-installed-files-from-a-package
dpkg-deb -c metasploit-framework_5.0.30+20190614201450~1rapid7-1_amd64.deb 

/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 130

ubuntu@ubuntu:~/smash$ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 130
Traceback (most recent call last):
	3: from /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb:16:in `<main>'
	2: from /usr/lib/ruby/2.5.0/rubygems/core_ext/kernel_gem.rb:65:in `gem'
	1: from /usr/lib/ruby/2.5.0/rubygems/dependency.rb:322:in `to_spec'
/usr/lib/ruby/2.5.0/rubygems/dependency.rb:310:in `to_specs': Could not find 'rex-text' (>= 0) among 28 total gem(s) (Gem::MissingSpecError)
Checked in 'GEM_PATH=/home/ubuntu/.gem/ruby/2.5.0:/var/lib/gems/2.5.0:/usr/lib/x86_64-linux-gnu/rubygems-integration/2.5.0:/usr/share/rubygems-integration/2.5.0:/usr/share/rubygems-integration/all', execute `gem env` for more information

https://github.com/rapid7/rex-text

gem install rex-text


ubuntu@ubuntu:~/smash$ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 130
[*] Bundler failed to load and returned this error:

   'cannot load such file -- bundler/setup'

[*] You may need to uninstall or upgrade bundler

ubuntu@ubuntu:~/smash$ sudo gem install bundler
Fetching: bundler-2.0.2.gem (100%)
Successfully installed bundler-2.0.2
Parsing documentation for bundler-2.0.2
Installing ri documentation for bundler-2.0.2
Done installing documentation for bundler after 6 seconds
1 gem installed

https://bundler.io/


ubuntu@ubuntu:~$ gem --version
2.7.6
ubuntu@ubuntu:~$ gem update --system
Updating rubygems-update
Fetching: rubygems-update-3.0.4.gem (100%)
ERROR:  While executing gem ... (Gem::FilePermissionError)
    You don't have write permissions for the /var/lib/gems/2.5.0 directory.
ubuntu@ubuntu:~$ sudo gem update --system
[sudo] password for ubuntu: 
Sorry, try again.
[sudo] password for ubuntu: 
Updating rubygems-update
Fetching: rubygems-update-3.0.4.gem (100%)
Successfully installed rubygems-update-3.0.4
Parsing documentation for rubygems-update-3.0.4
Installing ri documentation for rubygems-update-3.0.4
Installing darkfish documentation for rubygems-update-3.0.4
Done installing documentation for rubygems-update after 63 seconds
Parsing documentation for rubygems-update-3.0.4
Done installing documentation for rubygems-update after 0 seconds
Installing RubyGems 3.0.4
Bundler 1.17.3 installed
RubyGems 3.0.4 installed


ubuntu@ubuntu:~$ sudo gem update --system
Latest version already installed. Done.
ubuntu@ubuntu:~$ 


$ sudo gem install rake -v '12.3.2'
Fetching rake-12.3.2.gem
Successfully installed rake-12.3.2
Parsing documentation for rake-12.3.2
Installing ri documentation for rake-12.3.2
Done installing documentation for rake after 0 seconds


$ sudo gem install Ascii85 -v '1.0.3'
Fetching Ascii85-1.0.3.gem
Successfully installed Ascii85-1.0.3
Parsing documentation for Ascii85-1.0.3
Installing ri documentation for Ascii85-1.0.3
Done installing documentation for Ascii85 after 0 seconds
1 gem installed


$ sudo gem install concurrent-ruby -v '1.0.5'
Fetching concurrent-ruby-1.0.5.gem
Successfully installed concurrent-ruby-1.0.5
Parsing documentation for concurrent-ruby-1.0.5
Installing ri documentation for concurrent-ruby-1.0.5
Done installing documentation for concurrent-ruby after 6 seconds
1 gem installed


$ sudo gem install i18n -v '0.9.5'
Fetching i18n-0.9.5.gem
Successfully installed i18n-0.9.5
Parsing documentation for i18n-0.9.5
Installing ri documentation for i18n-0.9.5
Done installing documentation for i18n after 0 seconds
1 gem installed


$ sudo gem install minitest -v '5.11.3'
Fetching minitest-5.11.3.gem
Successfully installed minitest-5.11.3
Parsing documentation for minitest-5.11.3
Installing ri documentation for minitest-5.11.3
Done installing documentation for minitest after 1 seconds
1 gem installed


$ sudo gem install bundler
Successfully installed bundler-2.0.2
Parsing documentation for bundler-2.0.2
Done installing documentation for bundler after 5 seconds
1 gem installed

ubuntu@ubuntu:/opt/metasploit-framework/embedded/framework/tools/exploit$ ./pattern_create.rb -l 100
Could not find nokogiri-1.10.3 in any of the sources
Run `bundle install` to install missing gems.
ubuntu@ubuntu:/opt/metasploit-framework/embedded/framework/tools/exploit$ sudo gem install nokogiri -v '1.10.3'
Building native extensions. This could take a while...
ERROR:  Error installing nokogiri:
	ERROR: Failed to build gem native extension.

    current directory: /var/lib/gems/2.5.0/gems/nokogiri-1.10.3/ext/nokogiri
/usr/bin/ruby2.5 -I /usr/local/lib/site_ruby/2.5.0 -r ./siteconf20190616-1861-44cz3l.rb extconf.rb
mkmf.rb can't find header files for ruby at /usr/lib/ruby/include/ruby.h

extconf failed, exit code 1

Gem files will remain installed in /var/lib/gems/2.5.0/gems/nokogiri-1.10.3 for inspection.
Results logged to /var/lib/gems/2.5.0/extensions/x86_64-linux/2.5.0/nokogiri-1.10.3/gem_make.out
ubuntu@ubuntu:/opt/metasploit-framework/embedded/framework/tools/exploit$ 

https://nokogiri.org/tutorials/installing_nokogiri.html
sudo apt-get install build-essential patch ruby-dev zlib1g-dev liblzma-dev
gem install nokogiri

cd ~/sploit/metasploit-framework-master

bundle install


Gem files will remain installed in /tmp/bundler20190616-13489-igyupwpg-0.21.0/gems/pg-0.21.0 for inspection.
Results logged to /tmp/bundler20190616-13489-igyupwpg-0.21.0/extensions/x86_64-linux/2.5.0/pg-0.21.0/gem_make.out

An error occurred while installing pg (0.21.0), and Bundler cannot continue.
Make sure that `gem install pg -v '0.21.0' --source 'https://rubygems.org/'` succeeds before bundling.

In Gemfile:
  metasploit-framework was resolved to 5.0.30, which depends on
    metasploit-credential was resolved to 3.0.3, which depends on
      metasploit_data_models was resolved to 3.0.10, which depends on


 Installing pg 0.21.0 with native extensions
Gem::Ext::BuildError: ERROR: Failed to build gem native extension.

    current directory: /tmp/bundler20190616-13489-igyupwpg-0.21.0/gems/pg-0.21.0/ext
/usr/bin/ruby2.5 -I /usr/local/lib/site_ruby/2.5.0 -r ./siteconf20190616-13489-1nw8s69.rb extconf.rb
checking for pg_config... no


https://stackoverflow.com/questions/46411700/gem-pg-not-installing
sudo apt-get install postgresql-common
sudo apt-get install postgresql libpq-dev
sudo gem install pg -v '0.21.0' --source 'https://rubygems.org/'


bundle install


make failed, exit code 2

Gem files will remain installed in /tmp/bundler20190616-17494-67wdfnpcaprub-0.13.0/gems/pcaprub-0.13.0 for inspection.
Results logged to /tmp/bundler20190616-17494-67wdfnpcaprub-0.13.0/extensions/x86_64-linux/2.5.0/pcaprub-0.13.0/gem_make.out

An error occurred while installing pcaprub (0.13.0), and Bundler cannot continue.
Make sure that `gem install pcaprub -v '0.13.0' --source 'https://rubygems.org/'` succeeds before bundling.

In Gemfile:
  metasploit-framework was resolved to 5.0.30, which depends on
    packetfu was resolved to 1.1.13, which depends on
      pcaprub


 sudo gem install pcaprub -v '0.13.0' --source 'https://rubygems.org/'

sudo apt-get install libpcap-dev

ubuntu@ubuntu:~/sploit/metasploit-framework-master$ sudo gem install pcaprub -v '0.13.0' --source 'https://rubygems.org/'
Building native extensions. This could take a while...
Successfully installed pcaprub-0.13.0
Parsing documentation for pcaprub-0.13.0
Installing ri documentation for pcaprub-0.13.0
Done installing documentation for pcaprub after 0 seconds
1 gem installed


An error occurred while installing sqlite3 (1.3.13), and Bundler cannot continue.
Make sure that `gem install sqlite3 -v '1.3.13' --source 'https://rubygems.org/'` succeeds before bundling.

In Gemfile:
  metasploit-framework was resolved to 5.0.30, which depends on


gem install sqlite3 -v '1.3.13' --source 'https://rubygems.org/'


sudo apt-get install libsqlite3-dev


After this operation, 2,124 kB of additional disk space will be used.
Get:1 http://archive.ubuntu.com/ubuntu bionic/main amd64 libsqlite3-dev amd64 3.22.0-1 [632 kB]
Fetched 632 kB in 1s (695 kB/s)         
Selecting previously unselected package libsqlite3-dev:amd64.
(Reading database ... 126666 files and directories currently installed.)
Preparing to unpack .../libsqlite3-dev_3.22.0-1_amd64.deb ...
Unpacking libsqlite3-dev:amd64 (3.22.0-1) ...
Setting up libsqlite3-dev:amd64 (3.22.0-1) ...
ubuntu@ubuntu:~/sploit/metasploit-framework-master$ sudo gem install pcaprub -v '0.13.0' --source 'https://rubygems.org/'
Building native extensions. This could take a while...
Successfully installed pcaprub-0.13.0
Parsing documentation for pcaprub-0.13.0
Done installing documentation for pcaprub after 0 seconds
1 gem installed


Installing yard 0.9.19
Bundle complete! 14 Gemfile dependencies, 135 gems now installed.
Use `bundle info [gemname]` to see where a bundled gem is installed.
Post-install message from yard:
--------------------------------------------------------------------------------
As of YARD v0.9.2:

RubyGems "--document=yri,yard" hooks are now supported. You can auto-configure
YARD to automatically build the yri index for installed gems by typing:

    $ yard config --gem-install-yri

See `yard config --help` for more information on RubyGems install hooks.

You can also add the following to your .gemspec to have YARD document your gem
on install:

    spec.metadata["yard.run"] = "yri" # use "yard" to build full HTML docs.

--------------------------------------------------------------------------------

finally ---


ubuntu@ubuntu:/opt/metasploit-framework/embedded/framework/tools/exploit$ ./pattern_create.rb -l 140
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae
ubuntu@ubuntu:/opt/metasploit-framework/embedded/framework/tools/exploit$ 


------------------------------------------------

```

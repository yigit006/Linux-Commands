# 🐧 Temel Linux Komutları | Basic Linux Commands

Bu döküman, temel Linux terminal komutlarını Türkçe ve İngilizce olarak içeren iki ayrı bölümü katlanabilir şekilde sunar.  
This document presents basic Linux terminal commands in two collapsible sections for Turkish and English.

---

<details>
<summary>En English</summary>

```
Basic Linux Terminal Commands	

1. cd (Change Directory)

cd	            Go to the user's home directory.
cd ~	            Go to the home directory (same as cd).
cd ..	            Go up one directory level.
cd -	            Return to the previous directory.
cd /var/log	    Go to the specified directory (absolute path).
cd ../Desktop	    Go to the Desktop folder in the parent directory.


2. pwd (Print Working Directory)

pwd        Show the full path of the current directory.
pwd -P     Show the real path without following symbolic links.


3. ls (List Files)ls List directory contents.

ls -l       Long listing (permissions, size, date).
ls -a       Show hidden files (starting with .).
ls -lh      Show file sizes in human-readable format (KB, MB).
ls -t       Sort by modification time, newest first.
ls -R       List subdirectories recursively.
ls *.txt    List only files with the .txt extension.
ls -d */    List only directories.


4. cp (Copy Files)cp file new_file Copy a file.

cp -r directory/ new_directory/     Copy directories recursively.
cp -i file target/                  Prompt before overwriting.
cp -u source/* target/              Copy only when the source file is newer than the destination file or when the destination file is missing.
cp -v file target/                  Explain what is being done (verbose).


5. rm (Remove Files)rm file.txt Remove (delete) a file.

rm -i file.txt            Prompt before every removal.
rm -f file.txt            Force removal without prompting (use with caution!).
rm -r directory/          Remove a directory and its contents recursively.
rm -rf directory/         Force remove a directory and its contents recursively (use with extreme caution!).


6. mkdir (Make Directory)

mkdir new_directory        Create a new directory.
mkdir -p a/b/c             Create parent directories as needed.
mkdir -m 755 directory/    Create a directory with specific permissions.


7. rmdir (Remove Empty Directory)

rmdir empty_directory     Remove an empty directory.
rmdir -p a/b/c            Remove empty parent directories.


8. mv (Move/Rename Files)

mv old.txt new.txt               Rename a file.
mv file /target/directory/       Move a file to another directory.
mv -i file target/               Prompt before overwriting.
mv -u source/* target/           Move only when the source file is newer than the destination file or when the destination file is missing.


9. cat (Concatenate and Display File Content)

cat file.txt               Display the content of a file.
cat -n file.txt            Display file content with line numbers.
cat file1.txt file2.txt    Concatenate and display multiple files.
cat > new_file.txt         Create a new file and write to it (Save with Ctrl+D).


10. less / more (Display File Content Page by Page)

less file.txt                Display file content page by page (quit with 'q').
more file.txt                A simpler pager (advance with spacebar).
less +F /var/log/syslog      Follow the file content live (quit follow mode with Ctrl+C).


11. head / tail (Display Beginning/End of a File)

head file.txt              Display the first 10 lines.
head -n 5 file.txt         Display the first 5 lines.
tail file.txt              Display the last 10 lines.
tail -n 20 file.txt        Display the last 20 lines.
tail -f /var/log/syslog    Follow the file content live (stop with Ctrl+C).


12. file (Determine File Type)

file file.txt           Show the file type (e.g., ASCII text, JPEG image).
file -i file.txt        Show the MIME type (e.g., text/plain).


13. wc (Word Count - Lines/Words/Characters)

wc file.txt          Show line, word, and character counts.
wc -l file.txt       Show only the line count.
wc -w file.txt       Show only the word count.
wc -c file.txt       Show only the byte (character) count.


14. find (Search for Files/Directories)

find / -name "file.txt"         Search the entire system for file.txt.
find ~ -type f -name "*.mp3"    Find all MP3 files in the home directory.
find /var/log -size +10M        Find files larger than 10MB in /var/log.
find / -mtime -7                List files modified in the last 7 days.


15. grep (Search Text Patterns)

grep "word" file.txt           Search for "word" in the file.
grep -i "word" file.txt        Case-insensitive search.
grep -r "word" /directory/     Recursive search within a directory.
grep -v "word" file.txt        Show lines that do not contain the word.
grep -c "word" file.txt        Count the number of matching lines.


16. chmod (Change File Permissions)

chmod +x file.sh                 Add execute permission.
chmod 755 file.sh                Set permissions to rwxr-xr-x (owner=rwx, group=rx, others=rx).
chmod u=rw,g=r,o=r file.txt      Set specific permissions (user=read/write, group=read, others=read).
chmod -R 644 /directory/         Recursively set permissions to 644 (rw-r--r--) for all files in the directory.


17. chown (Change File Owner and Group)

chown user:group file.txt      Change the owner and group.
chown -R user: directory/      Recursively change the owner for all files in the directory.


18. ps (List Processes)

ps                 Show processes for the current terminal.
ps aux             Show all running processes in detail (BSD style).
ps -ef             Show all running processes with full command listing (System V style).
ps -u username     List processes owned by a specific user.


19. top / htop (System Resource Usage)

top                  Display CPU, RAM, and process usage live (quit with 'q').
htop                 An enhanced, interactive, and colorful version of top.
top -u username      Show processes for a specific user in top.


20. kill (Terminate Processes)

kill PID           Terminate a process normally (send SIGTERM).
kill -9 PID        Forcefully terminate a process (send SIGKILL).
killall firefox    Terminate all processes named 'firefox'.


21. df (Disk Free - Show Disk Usage)

df 	         Show usage for all mounted filesystems.
df -h	         Show sizes in human-readable format (GB/MB).
df -i 	         Show inode usage.
df -T 	         Show the filesystem type (ext4, NTFS, etc.).


22. mount / umount (Mount/Unmount Filesystems)

mount 	                           List all currently mounted filesystems.
mount /dev/sdb1 /mnt               Mount a disk partition to the /mnt directory.
mount -t ntfs /dev/sdb1 /mnt       Mount an NTFS partition.
umount /mnt                        Unmount the filesystem mounted at /mnt.


23. tar (Archive Creation/Extraction)

tar -cvf archive.tar files/            Create a new .tar archive. (c: create, v: verbose, f: file)
tar -xvf archive.tar                   Extract files from a .tar archive. (x: extract)
tar -czvf archive.tar.gz files/        Create a gzip compressed tar archive. (z: gzip)
tar -xzvf archive.tar.gz               Extract files from a gzip compressed tar archive.


24. gzip / gunzip (Compression/Decompression)

gzip file.txt                  Compress a file (creates file.txt.gz).
gunzip file.txt.gz             Decompress a .gz file.
gzip -9 file.txt               Use maximum compression.


25. rsync (File Synchronization)

rsync -av source/ target/                    Synchronize files efficiently. (a: archive mode, v: verbose)
rsync -avz source/ user@server:/target/      Synchronize to a remote server via SSH. (z: compress)
rsync --delete source/ target/               Delete files in the target that don't exist in the source.


26. crontab (Scheduled Tasks)

crontab -e        Edit or create cron jobs.
crontab -l        List current cron jobs.
crontab -r        Remove all cron jobs.

Example Cron Format:
# Minute Hour DayOfMonth Month DayOfWeek Command
* * * * * /path/to/script.sh  # Run every minute
0 3 * * * /backup.sh          # Run every day at 3:00 AM


27. apt / dpkg (Package Management - Debian/Ubuntu)

sudo apt update                    Update package lists.
sudo apt install package           Install a package.
sudo apt remove package            Remove a package.
sudo apt purge package             Remove a package along with its configuration files.
dpkg -i package.deb                Manually install a .deb package.


28. yum / dnf (Package Management - RHEL/CentOS/Fedora)

sudo yum install package            Install a package (older systems).
sudo yum remove package             Remove a package (older systems).
sudo dnf install package            Install a package (newer systems).
sudo dnf remove package             Remove a package (newer systems).
sudo dnf update                     Update all packages (newer systems).


29. ifconfig / ip (Network Management)

ifconfig            Show network interfaces (deprecated).
ip a                Modern alternative to show network interfaces.
ip route            Show the routing table.


30. ping (Test Network Connectivity)

ping google.com              Test connectivity using ICMP packets.
ping -c 4 google.com         Send only 4 packets.


31. ssh (Secure Shell - Remote Login)

ssh user@server                        Connect to a remote server via SSH.
ssh -p 2222 user@server                Connect using a specific port.
ssh -i ~/.ssh/key.pem user@server      Connect using an SSH key file.


32. scp (Secure Copy - Remote File Transfer)

scp file.txt user@server:/target/            Copy a file to a remote server.
scp -r directory/ user@server:/target/       Copy a directory recursively to a remote server.


33. wget / curl (Download Files from Internet)

wget https://example.com/file.zip           Download a file.
curl -O https://example.com/file.zip        Download a file using curl.
wget --mirror https://site.com              Mirror an entire website (use responsibly).


34. iptables (Firewall Management)

iptables -L                                        List current firewall rules.
iptables -A INPUT -p tcp --dport 22 -j ACCEPT      Allow incoming SSH connections (port 22).
iptables -F                                        Flush (clear) all rules.


35. journalctl (View System Logs - systemd)

journalctl                           Show all system logs.
journalctl -u nginx                  Show logs for the nginx service unit.
journalctl --since "2024-01-01"      List logs since a specific date.


36. useradd / userdel (User Management)

sudo useradd username              Create a new user.
sudo userdel -r username           Delete a user and their home directory.
sudo passwd username               Change the password for a user.


37. passwd (Change Password)

passwd                 Change the current user's password.
sudo passwd root       Change the root user's password.


38. vi / vim (Text Editing)

vi file.txt           Open a file for editing.
vim file.txt          Open a file with the enhanced Vim editor.

Basic Vim Commands:
i         Enter Insert mode.
Esc       Exit Insert mode (return to Normal mode).
:w        Save changes.
:q        Quit.
:wq       Save and quit.
:q!       Quit without saving changes.


39. history (Command History)

history          Show the command history list.
!123             Re-run command number 123 from history.
!!               Re-run the last command.
history -c       Clear the command history.


40. uname (System Information)

uname -a     Show all system information.
uname -r     Show the kernel release version.



Additional Terminal Commands

1.System and Hardware Information

lscpu                  Display information about the CPU architecture.
lsblk                  List block devices (disks, partitions).
lspci                  List all PCI devices (e.g., GPU, NIC).
lsusb                  List USB devices.
dmidecode              Display hardware information from DMI/SMBIOS (RAM, BIOS).
hdparm -i /dev/sda     Show disk model and features (replace sda if needed).


2. Network Tools

nmap                      Network exploration tool and security/port scanner.
traceroute                Print the route packets trace to network host.
netstat -tuln             List listening TCP and UDP ports and connections (older).
ss -lntp                  Socket statistics, modern alternative to netstat.
dig google.com            DNS lookup utility, shows detailed DNS information.
whois domain.com          Query domain registration information.
iftop                     Display bandwidth usage on an interface by host (live).


3. File and Text Processing

rename 's/\.txt$/.md/' *.txt                               Rename file extensions from .txt to .md.
stat file.txt                                              Display file or file system status (access/modify times).
shred -v -n 5 -z file.txt                                  Securely delete a file by overwriting it (irreversible). (v: verbose, n 5: overwrite 5 times, z: final overwrite with zeros)
cmp file1 file2                                            Compare two files byte by byte.
comm -3 file1 file2                                        Compare two sorted files line by line, showing lines unique to file1 and file2 (-3 suppresses common lines).
iconv -f ISO-8859-9 -t UTF-8 file.txt > output.txt         Convert file encoding (e.g., from Turkish ISO to UTF-8).


4. Process and Performance Monitoring

iotop               Monitor disk I/O usage by process (live).
nethogs             Monitor network traffic usage by process (live).
glances             An eye on your system. A top/htop alternative with more info.
strace -p PID       Trace system calls and signals for a process.
lsof -i :80         List open files (including network sockets) using port 80.


5. User and Security

who -b                   Show the time of last system boot.
last                     Show a listing of last logged in users.
faillock                 Display and modify authentication failure records.
chage -l username        Display user password expiration information.
getfacl /directory       Get file access control lists (ACLs).


6. Archive and Compression

zcat file.gz           Display compressed file content without decompressing.
unrar x file.rar       Extract files from a RAR archive.
7z x file.7z           Extract files from a 7-Zip archive.


7. Advanced Disk Operations

badblocks -v /dev/sda         Check a device for bad sectors (use with caution, potentially destructive).
smartctl -a /dev/sda          Control and monitor utility for SMART disks (shows health status).
parted -l                     List disk partition tables.


8. Terminal and Shell Tools

tmux                      Terminal multiplexer (manage multiple terminal sessions).
screen                    Alternative terminal multiplexer.
watch -n 1 "ls -l"        Execute a program periodically, showing output fullscreen (updates ls -l every 1 second).
script                    Make a typescript of a terminal session (records everything).


9. Visual and Multimedia (Command Line)

ffmpeg                 Powerful tool for converting and manipulating audio/video files.
convert                Convert between image formats (part of ImageMagick).
mpv file.mp4           Command-line media player.


10. Other Useful Tools

tree                  List contents of directories in a tree-like format.
ncdu                  NCurses Disk Usage analyzer (interactive).
cal                   Display a calendar.
factor 42             Print the prime factors of a number.
curl ifconfig.me      Show your external IP address.
```

</details>

<details>
<summary>Tr Türkçe</summary>

```
Temel Linux Komutları

1. cd (Dizin Değiştirme)

cd	            Kullanıcının ev dizinine gider.
cd ~	            Ev dizinine gider (cd ile aynı).
cd .. 	            Bir üst dizine çıkar.
cd -	            Önceki dizine döner.
cd /var/log	    Belirtilen dizine gider (mutlak yol).
cd ../Desktop	    Bir üst dizindeki Desktop klasörüne gider.


2. pwd (Bulunulan Dizini Göster)

pwd	    Şu anki dizinin tam yolunu gösterir.
pwd -P      Sembolik linkleri takip etmeden gerçek yolu gösterir.


3. ls (Dosya Listeleme)

ls	        Dizin içeriğini listeler.
ls -l	        Uzun liste (izinler, boyut, tarih).
ls -a	        Gizli dosyaları gösterir.
ls -lh          Dosya boyutlarını okunabilir formatta gösterir (KB, MB).
ls -t	        Değiştirilme tarihine göre sıralar.
ls -R	        Alt dizinlerle birlikte listeler.
ls *.txt	Sadece .txt uzantılı dosyaları listeler.
ls -d */	Sadece dizinleri listeler.


4. cp (Dosya Kopyalama)

cp dosya yeni_dosya	        Dosyayı kopyalar.
cp -r dizin/ yeni_dizin/	Dizinleri kopyalar.
cp -i dosya hedef/	        Üzerine yazmadan önce onay ister.
cp -u kaynak/* hedef/	        Sadece güncel dosyaları kopyalar.
cp -v dosya hedef/	        Kopyalama işlemini detaylı gösterir.


5. rm (Dosya Silme)

rm dosya.txt	        Dosyayı siler.
rm -i dosya.txt	        Silmeden önce onay ister.
rm -f dosya.txt	        Onay sormadan zorla siler.
rm -r dizin/	        Dizin ve içeriğini siler.
rm -rf dizin/	        Dizin ve altındakileri sorunsuz siler (Dikkatli kullan!).


6. mkdir (Dizin Oluşturma)

mkdir yeni_dizin	  Yeni bir dizin oluşturur.
mkdir -p a/b/c	          İç içe dizinleri oluşturur.
mkdir -m 755 dizin/	  Belirli izinlerle dizin oluşturur.


7. rmdir (Boş Dizin Silme)

rmdir bos_dizin	       Boş bir dizini siler.
rmdir -p a/b/c	       İç içe boş dizinleri siler.


8. mv (Dosya Taşıma/Yeniden Adlandırma)

mv eski.txt yeni.txt     	Dosyayı yeniden adlandırır.
mv dosya /hedef/dizin/	        Dosyayı başka bir dizine taşır.
mv -i dosya hedef/	        Üzerine yazmadan önce onay ister.
mv -u kaynak/* hedef/	        Sadece güncel dosyaları taşır.


9. cat (Dosya İçeriğini Görüntüleme)

cat dosya.txt	                Dosya içeriğini gösterir.
cat -n dosya.txt	        Satır numaralarıyla gösterir.
cat dosya1.txt dosya2.txt	Birden fazla dosyayı birleştirir.
cat > yeni_dosya.txt	        Yeni dosya oluşturup içine yazmaya başlar (Ctrl+D ile kaydeder).


10. less / more (Sayfa Sayfa Dosya Görüntüleme)

less dosya.txt	             Dosyayı sayfa sayfa gösterir (q ile çıkış).
more dosya.txt	             Basit bir sayfa görüntüleyici (space ile ilerler).
less +F /var/log/syslog	     Dosyayı canlı takip eder (Ctrl+C ile çıkar).


11. head / tail (Dosyanın Başını/Sonunu Görüntüleme)

head dosya.txt	                İlk 10 satırı gösterir.
head -n 5 dosya.txt	        İlk 5 satırı gösterir.
tail dosya.txt	                Son 10 satırı gösterir.
tail -n 20 dosya.txt	        Son 20 satırı gösterir.
tail -f /var/log/syslog	        Dosyayı canlı takip eder (Ctrl+C ile durdurur).


12. file (Dosya Türünü Belirleme)

file dosya.txt	          Dosyanın türünü gösterir (ör: ASCII text, JPEG image).
file -i dosya.txt	  MIME türünü gösterir (ör: text/plain).


13. wc (Satır/Kelime/Karakter Sayma)

wc dosya.txt	        Satır, kelime ve karakter sayısını gösterir.
wc -l dosya.txt	        Sadece satır sayısını verir.
wc -w dosya.txt	        Sadece kelime sayısını verir.
wc -c dosya.txt	        Sadece karakter sayısını verir.


14. find (Dosya/Dizin Arama)

find / -name "dosya.txt"	  Tüm sistemde dosya.txt arar.
find ~ -type f -name "*.mp3" 	  Ev dizinindeki tüm MP3 dosyalarını bulur.
find /var/log -size +10M	  10MB’dan büyük dosyaları arar.
find / -mtime -7	          Son 7 günde değiştirilen dosyaları listeler.


15. grep (Metin Arama)

grep "kelime" dosya.txt	  Dosyada kelime arar.
grep -i "kelime" dosya.txt	  Büyük/küçük harf duyarsız arama.
grep -r "kelime" /dizin/	  Dizin içinde rekürsif arama yapar.
grep -v "kelime" dosya.txt	  Kelime içermeyen satırları gösterir.
grep -c "kelime" dosya.txt	  Kaç kez geçtiğini sayar.


16. chmod (Dosya İzinlerini Değiştirme)

chmod +x dosya.sh	            Çalıştırma izni verir.
chmod 755 dosya.sh	            rwxr-xr-x izinleri atar.
chmod u=rw,g=r,o=r dosya.txt	    Kullanıcıya okuma-yazma, gruba ve diğerlerine sadece okuma izni verir.
chmod -R 644 /dizin/	            Tüm dosyalara 644 izni verir (rekürsif).


17. chown (Dosya Sahibini Değiştirme)

chown kullanici:grup dosya.txt	        Sahip ve grubunu değiştirir.
chown -R kullanici:dizin/	        Dizindeki tüm dosyaların sahibini değiştirir.


18. ps (Süreçleri Listeleme)

ps	                 Mevcut terminaldeki süreçleri gösterir.
ps aux	                 Tüm süreçleri detaylı listeler.
ps -ef	                 Tam komut listesiyle süreçleri gösterir.
ps -u kullanici 	 Belirli bir kullanıcının süreçlerini listeler.


19. top / htop (Sistem Kaynak Kullanımı)

top	                CPU, RAM ve süreç kullanımını canlı gösterir.
htop	                Daha gelişmiş ve renkli versiyonu.
top -u kullanici	Belirli bir kullanıcının süreçlerini gösterir.


20. kill (Süreç Sonlandırma)

kill PID	        Süreci normal şekilde sonlandırır.
kill -9 PID	        Süreci zorla sonlandırır.
killall firefox	        Tüm Firefox süreçlerini kapatır.


21. df (Disk Kullanımını Göster)

df	     Tüm disklerin kullanımını gösterir.
df -h	     Boyutları GB/MB cinsinden gösterir.
df -i	     Inode kullanımını gösterir.
df -T	     Dosya sistemi türünü gösterir (ext4, NTFS).


22. mount / umount (Dosya Sistemi Bağlama)

mount 	                         Bağlı tüm dosya sistemlerini listeler.
mount /dev/sdb1 /mnt	         Bir diski /mnt dizinine bağlar.
mount -t ntfs /dev/sdb1 /mnt	 NTFS diski bağlar.
umount /mnt	                 Bağlı dizini kaldırır.


23. tar (Arşiv Oluşturma/Açma)

tar -cvf arsiv.tar dosyalar/	        Yeni bir .tar arşivi oluşturur.
tar -xvf arsiv.tar	                Arşivi açar.
tar -czvf arsiv.tar.gz dosyalar/	Gzip ile sıkıştırılmış arşiv oluşturur.
tar -xzvf arsiv.tar.gz	                Gzip arşivini açar.


24. gzip / gunzip (Sıkıştırma/Açma)

gzip dosya.txt	         Dosyayı sıkıştırır (.gz yapar).
gunzip dosya.txt.gz  	 Sıkıştırılmış dosyayı açar.
gzip -9 dosya.txt	 Maksimum sıkıştırma yapar.


25. rsync (Dosya Senkronizasyonu)

rsync -av kaynak/ hedef/	                Dosyaları senkronize eder.
rsync -avz kaynak/ user@sunucu:/hedef/	        SSH ile uzak sunucuya senkronize eder.
rsync --delete kaynak/ hedef/	                Hedefte olmayan dosyaları siler.


26. crontab (Zamanlanmış Görevler)

crontab -e	Zamanlanmış görev ekler/düzenler.
crontab -l	Mevcut cron işlerini listeler.
crontab -r	Tüm cron işlerini siler.

Örnek Cron Formatı:
* * * * * /path/to/script.sh  # Her dakika çalıştır
0 3 * * * /backup.sh         # Her gün saat 03:00'te çalıştır


27. apt / dpkg (Paket Yönetimi - Debian/Ubuntu)

sudo apt update	                Paket listesini günceller.
sudo apt install paket	        Paket kurar.
sudo apt remove paket	        Paketi kaldırır.
sudo apt purge paket	        Paketi config dosyalarıyla siler.
dpkg -i paket.deb	        Manuel .deb paketi kurar.


28. yum / dnf (Paket Yönetimi - RHEL/CentOS/Fedora)

sudo yum install paket	        Paket kurar.
sudo yum remove paket	        Paketi kaldırır.
sudo dnf update	                Tüm paketleri günceller.


29. ifconfig / ip (Ağ Yönetimi)

ifconfig	Ağ arayüzlerini gösterir.
ip a	        Modern alternatif (ifconfig yerine).
ip route	Yönlendirme tablosunu gösterir.


30. ping (Ağ Bağlantısını Test Et)

ping google.com	             ICMP ile bağlantıyı test eder.
ping -c 4 google.com	     Sadece 4 paket gönderir.


31. ssh (Uzak Sunucuya Bağlan)

ssh user@sunucu	                        SSH ile bağlanır.
ssh -p 2222 user@sunucu	                Özel port kullanarak bağlanır.
ssh -i ~/.ssh/key.pem user@sunucu	SSH anahtarı ile bağlanır.


32. scp (Güvenli Dosya Transferi)

scp dosya.txt user@sunucu:/hedef/	Dosyayı uzak sunucuya kopyalar.
scp -r dizin/ user@sunucu:/hedef/	Dizini rekürsif kopyalar.


33. wget / curl (İnternetten Dosya İndirme)

wget https://ornek.com/dosya.zip	 Dosya indirir.
curl -O https://ornek.com/dosya.zip	 curl ile dosya indirir.
wget --mirror https://site.com	         Tüm siteyi indirir.


34. iptables (Güvenlik Duvarı Yönetimi)

iptables -L	                                    Kuralları listeler.
iptables -A INPUT -p tcp --dport 22 -j ACCEPT	    SSH bağlantısına izin verir.
iptables -F	                                    Tüm kuralları temizler.


35. journalctl (Sistem Loglarını Görüntüle)

journalctl	                        Tüm sistem loglarını gösterir.
journalctl -u nginx	                Nginx loglarını gösterir.
journalctl --since "2024-01-01"	        Belirli tarihten sonraki logları listeler.


36. useradd / userdel (Kullanıcı Yönetimi)

sudo useradd kullanici	        Yeni kullanıcı oluşturur.
sudo userdel -r kullanici	Kullanıcıyı ev diziniyle siler.
sudo passwd kullanici	        Kullanıcı şifresini değiştirir.


37. passwd (Şifre Değiştirme)

passwd	                Mevcut kullanıcının şifresini değiştirir.
sudo passwd root	Root şifresini değiştirir.


38. vi / vim (Metin Düzenleme)

vi dosya.txt	    Dosyayı düzenlemek için açar.
vim dosya.txt	    Daha gelişmiş sürüm (vim).
:wq	            Değişiklikleri kaydedip çıkar.
:q!	            Değişiklikleri kaydetmeden çıkar.


39. history (Komut Geçmişi)

history	        Tüm komut geçmişini gösterir.
!123	        123 numaralı komutu tekrar çalıştırır.
history -c	Geçmişi temizler.


40. uname (Sistem Bilgisi)

uname -a	Tüm sistem bilgilerini gösterir.
uname -r	Çekirdek sürümünü gösterir.




EK TERMİNAL KONUTLARI

1. Sistem ve Donanım Bilgisi

lscpu	                CPU bilgilerini gösterir.
lsblk  	                Blok cihazları (diskler, bölümler) listeler.
lspci 	                PCI aygıtlarını detaylı gösterir (örn: GPU, NIC).
lsusb	                Bağlı USB cihazlarını listeler.
dmidecode	        Donanım bilgilerini (RAM, BIOS) gösterir.
dparm -i /dev/sda	Disk modeli ve özelliklerini gösterir.


2. Ağ (Network) Araçları

nmap	                Ağ tarama ve port keşfi yapar.
traceroute	        Paketlerin izlediği yolu gösterir.
netstat -tuln	        Açık portları ve bağlantıları listeler.
ss -lntp	        netstat'ın modern alternatifi.
dig google.com	        DNS sorgularını detaylı gösterir.
whois domain.com	Domain bilgilerini sorgular.
iftop	                Ağ trafiğini canlı izler (bandwidth kullanımı).


3. Dosya ve Metin İşleme

rename 's/\.txt$/.md/' *.txt	                Dosya uzantılarını .txt'den .md'ye çevirir.
stat dosya.txt	                                Dosya erişim/değişim zamanlarını gösterir.
shred -v -n 5 -z dosya.txt	                Dosyayı güvenli şekilde siler (geri dönülemez).
cmp dosya1 dosya2	                        İki dosyayı bayt bayt karşılaştırır.
comm -3 dosya1 dosya2	                        İki dosyadaki farklı satırları gösterir.
iconv -f ISO-8859-9 -t UTF-8 dosya.txt	        Dosya kodlamasını değiştirir.


4. Süreç (Process) ve Performans İzleme

iotop	           Disk I/O kullanımını canlı gösterir.
nethogs	           Süreç bazında ağ trafiğini izler.
glances	           Sistem kaynaklarını renkli ve detaylı gösterir.
strace -p          PID	Sürecin sistem çağrılarını izler.
lsof -i :80	   80. portu kullanan süreçleri listeler.


5. Kullanıcı ve Güvenlik

who -b	                Sistemin son başlangıç zamanını gösterir.
last	                Oturum açan kullanıcıların geçmişini listeler.
faillock	        Başarısız giriş denemelerini gösterir.
chage -l kullanici	Kullanıcı şifre politikalarını listeler.
getfacl /dizin	        ACL (Access Control List) izinlerini gösterir.


6. Arşiv ve Sıkıştırma

zcat dosya.gz	        Sıkıştırılmış dosyayı açmadan okur.
unrar x dosya.rar	RAR arşivini açar.
7z x dosya.7z	        7-Zip arşivini açar.


7. Gelişmiş Disk İşlemleri

badblocks -v /dev/sda 	        Diskteki bozuk sektörleri tespit eder.
smartctl -a /dev/sda            Disk sağlık durumunu (SMART) gösterir.
parted -l	                Disk bölümlerini detaylı listeler.


8. Terminal ve Kabuk (Shell) Araçları

tmux	                Terminal çoklayıcı (pencere yönetimi).
screen	                Alternatif terminal çoklayıcı.
watch -n 1 "ls -l"	Komutu her saniye yeniler (ls -l'i canlı izler).
script	                Terminal oturumunu kaydeder.


9. Görsel ve Multimedya

ffmpeg	             Video/dönüştürme ve işleme aracı.
convert	             Resim formatını dönüştürür (ImageMagick).
mpv dosya.mp4	     Terminalde video oynatır.


10. Diğer Kullanışlı Araçlar

tree	                Dizin yapısını ağaç şeklinde gösterir.
ncdu	                Disk kullanımını interaktif analiz eder.
cal	                Takvimi gösterir.
factor 42	        Sayının asal çarpanlarını bulur.
curl ifconfig.me	Dış IP adresini gösterir.
```

</details>

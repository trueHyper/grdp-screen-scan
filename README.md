# grdp-screen-scan
golang rdp scanner/logon screenshot &amp; ntlm info

Just run "go build ./" in example folder
Run program "./example <ip:port>"

TODO
1. чтение сокетов из файла(json?) и их параллельная обработка (нужно вынести текущий main наверно в отдельный пакет, и потом уже дергать необходимю функцию как из библиотеки)
2. флаги (тот же -file для пункта выше)
3. почистить вывод в консоль от лишнего
4. ...

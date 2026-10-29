# Arch Linux x64

1. Создайте устройство **Linux** в [кабинете PrivetDNS](https://privetdns.ru/cabinet).
2. Скопируйте личное имя DoT вида `…dot.privetdns.ru`.
3. Распакуйте `PrivetDNS-Connect-Arch-x64.zip`.
4. Выполните в терминале `sudo ./PrivetDNS-Connect`.
5. Вставьте имя DoT на открывшейся странице и нажмите «Подключить».

После подключения терминал можно закрыть. Для отключения снова запустите приложение и нажмите «Отключить и восстановить DNS».

Требуются NetworkManager, systemd-resolved, systemd, `nmcli`, `resolvectl`, `ip`, `xdg-open` и Python 3. Дополнительные Python-пакеты не нужны.

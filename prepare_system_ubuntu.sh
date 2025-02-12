#!/bin/sh
cd ..
git clone https://github.com/Domain-Connect/Templates.git
groupadd --gid 1001 --system pda
adduser --uid 1001 --system --no-create-home --ingroup pda pda
chown -R pda:pda Templates
groupadd --gid 953 --system pdns
adduser --uid 953 --system --no-create-home --ingroup pdns pdns
groupadd --gid 1002 --system pdamysql
adduser --uid 1002 --system --no-create-home --ingroup pda pdamysql

#add cron job 
#10 0 * * * cd /root/Templates && ((git add . && git stash && git pull origin master --rebase -X theirs && (git stash pop || true) && (git restore --staged . || true) && (git stash clear || true)) || true) && chown pda:pda * &> /dev/null

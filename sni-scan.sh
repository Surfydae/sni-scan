#!/usr/bin/env bash
# =============================================================================
#  sni-scan.sh v1.2 — перебор SNI для СВОЕГО VLESS-сервера (Reality / TLS+Vision)
#
#  Что делает:
#   1) читает файл со списком доменов-кандидатов   (ключ -f / --file);
#   2) делает контрольный хендшейк со СЛУЧАЙНЫМ SNI — видно, какой
#      сертификат сервер отдаёт "по умолчанию"; у Reality это сертификат dest,
#      т.е. прямая подсказка, какой SNI надо ставить;
#   3) перебором пробует каждый SNI на указанный IP:PORT (ключи -i и -p):
#      TLS-хендшейк, версия TLS, шифр, ALPN, ключевой обмен (X25519),
#      валидность цепочки + совпадение имени, время хендшейка;
#   4) печатает таблицу, сортирует кандидатов по качеству, пишет TSV (-o).
#
#  Нужно: bash 4+, openssl 1.1.1+ (лучше 3.x), coreutils (timeout), xargs.
#  Лицензия: public domain / делай что хочешь.
# =============================================================================

set -uo pipefail

VERSION="1.4"

SELF="${BASH_SOURCE[0]}"
[[ "$SELF" == /* ]] || SELF="$PWD/$SELF"

# ------------------------------------------------------------- параметры -----
# Значения по умолчанию берутся из окружения: так их получают воркеры xargs.
FILE="${SNIS_FILE:-}"
HOSTIP="${SNIS_IP:-}"
PORT="${SNIS_PORT:-443}"
TMO="${SNIS_TIMEOUT:-5}"
JOBS="${SNIS_JOBS:-16}"
OUT="${SNIS_OUT:-}"
NO_OUT="${SNIS_NO_OUT:-0}"
ALPN="${SNIS_ALPN:-h2,http/1.1}"
ANY_TLS="${SNIS_ANY_TLS:-0}"
DO_HTTP="${SNIS_DO_HTTP:-0}"
HTTP_WAIT="${SNIS_HTTP_WAIT:-1}"
ONLY_GOOD="${SNIS_ONLY_GOOD:-0}"
NEED_DNS="${SNIS_NEED_DNS:-0}"
NO_BASELINE="${SNIS_NO_BASELINE:-0}"
TOPN="${SNIS_TOPN:-0}"
NOCOLOR="${SNIS_NOCOLOR:-0}"
MODE="scan"
PROBE_SNI=""

# ---------------------------------------------------- встроенный список ----
# Используется, когда -f/--file не задан. Порядок: сначала базовый список
# (рос. сервисы: yandex/vk/2gis/rzd/ozon/wb/gosuslugi...), затем cert-domain
# из вашего скана (только без '*'). Посмотреть: ./sni-scan.sh --print-list
builtin_list() {
	cat <<'SNI_LIST'
# --- базовый список (188) ---
hcaptcha.com
okkam.group
vk.com
2gis.com
2gis.ru
300.ya.ru
ad.adriver.ru
3475482542.mc.yandex.ru
742231.ms.ok.ru
a.wb.ru
ad.mail.ru
adm.mp.rzd.ru
akashi.vk-portal.net
alfabank.ru
web.max.ru
ams2-cdn.2gis.com
an.yandex.ru
api-maps.yandex.ru
api.2gis.ru
api.avito.ru
api.browser.yandex.com
api.browser.yandex.ru
api.events.plus.yandex.net
api.mindbox.ru
api.photo.2gis.com
api.reviews.2gis.com
avatars.mds.yandex.com
avatars.mds.yandex.net
avito.ru
banners-website.wildberries.ru
bot.gosuslugi.ru
bro-bg-store.s3.yandex.com
bro-bg-store.s3.yandex.net
bro-bg-store.s3.yandex.ru
brontp-pre.yandex.ru
browser.yandex.com
browser.yandex.ru
cargo.rzd.ru
catalog.api.2gis.com
cdn.lemanapro.ru
cdn.yandex.ru
cdnrhkgfkkpupuotntfj.svc.cdn.yandex.net
chat-prod.wildberries.ru
chat3.vtb.ru
cloud.cdn.yandex.com
cloud.cdn.yandex.net
cloud.cdn.yandex.ru
cloudcdn-ams19.cdn.yandex.net
collections.yandex.com
collections.yandex.ru
company.rzd.ru
contacts.rzd.ru
contract.gosuslugi.ru
cs.avito.ru
csp.yandex.net
d-assets.2gis.ru
disk.2gis.com
disk.rzd.ru
dmp.dmpkit.lemanapro.ru
dr.yandex.net
dr2.yandex.net
dzen.ru
egress.yandex.net
eh.vk.com
ekmp-a-51.rzd.ru
enterprise.api-maps.yandex.ru
esia.gosuslugi.ru
favorites.api.2gis.com
favicon.yandex.com
favicon.yandex.net
favicon.yandex.ru
filekeeper-vod.2gis.com
frontend.vh.yandex.ru
gosuslugi.ru
i0.photo.2gis.com
i1.photo.2gis.com
i2.photo.2gis.com
i3.photo.2gis.com
i4.photo.2gis.com
i5.photo.2gis.com
i6.photo.2gis.com
i7.photo.2gis.com
i8.photo.2gis.com
i9.photo.2gis.com
id.sber.ru
jam.api.2gis.com
keys.api.2gis.com
kiks.yandex.com
kiks.yandex.ru
lemanapro.ru
link.mp.rzd.ru
lk.gosuslugi.ru
log.strm.yandex.ru
login.vk.com
m.avito.ru
mail.yandex.com
mail.yandex.ru
map.gosuslugi.ru
mapgl.2gis.com
market.rzd.ru
mc.yandex.com
mc.yandex.ru
mddc.tinkoff.ru
mediafeeds.yandex.com
mediafeeds.yandex.ru
metrics.alfabank.ru
mp.rzd.ru
my.rzd.ru
neuro.translate.yandex.ru
novorossiya.gosuslugi.ru
ok.ru
ozon.ru
partners.gosuslugi.ru
partners.lemanapro.ru
personalization-web-stable.mindbox.ru
pos.gosuslugi.ru
privacy-cs.mail.ru
prodvizhenie.rzd.ru
public-api.reviews.2gis.com
pulse.mp.rzd.ru
queuev4.vk.com
rs.mail.ru
rzd.ru
s.vtb.ru
s0.bss.2gis.com
s1.bss.2gis.com
s3.yandex.net
sba.yandex.com
sba.yandex.net
sba.yandex.ru
secure-cloud.rzd.ru
secure.rzd.ru
sfd.gosuslugi.ru
sntr.avito.ru
speller.yandex.net
splitter.wb.ru
sso-app4.vtb.ru
sso-app5.vtb.ru
sso.dzen.ru
st-ok.cdn-vk.ru
st.avito.ru
static-mon.yandex.net
static.lemanapro.ru
stats.avito.ru
stats.vk-portal.net
storage.ape.yandex.net
strm-rad-23.strm.yandex.net
strm-spbmiran-08.strm.yandex.net
strm.yandex.net
strm.yandex.ru
styles.api.2gis.com
suggest.dzen.ru
suggest.sso.dzen.ru
surveys.yandex.ru
sync.browser.yandex.net
team.rzd.ru
ticket.rzd.ru
tile0.maps.2gis.com
tile1.maps.2gis.com
tile2.maps.2gis.com
tile3.maps.2gis.com
tile4.maps.2gis.com
top-fwz1.mail.ru
travel.rzd.ru
user-geo-data.wildberries.ru
vk-portal.net
wap.yandex.com
wap.yandex.ru
wb.ru
web-static.mindbox.ru
welcome.rzd.ru
widgets.cbonds.ru
www.avito.ru
www.gosuslugi.ru
www.ozon.ru
www.rzd.ru
www.vtb.ru
www.wildberries.ru
xapi.ozon.ru
yabro-wbplugin.edadeal.yandex.ru
yabs.yandex.ru
yandex.com
yandex.net
yandex.ru
yastatic.net
zen-yabro-morda.mediascope.mc.yandex.ru
zen.yandex.com
zen.yandex.net
zen.yandex.ru

# --- cert-domain из скана, без wildcard (552) ---
okkam.group
www.aegisapp.ru
actibo.ru
video.bratan.fun
go-dahab.ru
seturbo.ru
gallery11.ru
hyal-system.ru
vm2306012873.vds.ru
smmanalyzer.ru
carports-lk.pro
app.homies-mag.by
timesrv2.infograd.online
interview.superresearch.ru
bxtest.jjkk.ru
www.ecogr.ru
itcontact.pro
conf.liskifitting.ru
cvt-l.ru
lk.3dkzn.ru
distlife.ru
dosotki.ru
xn--e1asbf2d.xn--p1ai
agv.ru
www.eshe.pizza
mactak-m.ru
symptomov.net
vm2507318243.vds.ru
svoygarage.ru
old.sezar-group.ru
www.rocketroll.com
email.labdv.ru
nppmera.ru
ozk-group.ru
ot-contact.com
www.in-systems.ru
timesrv1.infograd.online
timesrv6.infograd.online
karibiya.ru
timesrv3.infograd.online
vemata.ru
rentalc.ru
www.razo10.ru
aixio.ru
addressbook.bngroup.ru
doctor-tm.ru
www.tmf-apps.ru
aiteria.ru
test.fokm.ru
infsoft.ru
amgcorporation.ru
anticor-m.ru
tiros-tool.ru
cp.one-zhk.ru
cp.zhk-jois.ru
qwe.xn--14-6kcd0fg.xn--p1ai
school537.spb.ru
ksdfo.rspp.ru
www.transparent-flows.ru
radi-videoigr.ru
consulting.k2.tech
admin-new.beta-rnsprt.ru
feed.villa-crimea.ru
chukotkomhoz.ru
test.eosguru.ru
umniesvyazi.ru
achimgaz.ru
www.xn----8sbaatesaqfhac5a9aln.xn--p1ai
gk-nauka.ru
wiki.appliedrobotics.ru
xn--80aygu.xn--p1ai
raochgk.ru
dom-innovator.ru
65years.promomed.pro
icecert.cniimf.ru
euparts22.ru
winesandspirits.ru
en.pantis.com
pir.bivector.ru
capcontrol.pro
www.ckk.su
sfa.ru
www.burnier.vin
bnpz.tech
lsk.expert
vityaz-school.ru
personal.lithium.ru
timesrv5.infograd.online
merkatorgroup.ru
ogea.ru
eworkbook.ru
femibion.ru
sever-hub.ru
www.itpromtech.ru
www.crp-robot.ru
converse.newbizline.ru
stknur.ru
aodim.ru
timesrv7.infograd.online
dreamriva.ru
timesrv4.infograd.online
bbp.ru
timesrv.infograd.online
cyberapps.ru
profuchaly.ru
gm-board.ru
content-type.ru
csdev.rnrc.ru
adm.py86.ru
ostec-smart.ru
banquet.hotelsama-ra.ru
aeondevelopment.ru
git.oxota.beer
www.papps.pro
www.ton-centre.ru
widget.performia-seminar.online
lifeline.house
opagpt.ru
p676079.kvm.ihc.ru
lk.coipk.net
admin-dev.monyfix.tech
gitlab.techcon.pro
www.clife.ru
invest.admugansk.ru
farmoborona.site
climati.ru
gitlab.max.team
amocrm.suhin.ru
beribanyu.ru
app.vodokanalku.ru
img.extra-frosty.pro
vip-logistik.ru
xn--80ajykr.xn--p1ai
dalkmarket.ru
aichat.octweb.ru
domov.bemalan.cz
ru.bookm8.cc
potolki-aktis.ru
zvetnoe.ru
gipersport.ru
erp.legen-auto.ru
gdz.top
bd.sv34.ru
apimt.gdz-ru.com
rusik.cloud134.ru
onnode1.zabbix.fun
yankie.ru
tr.nscar.ru
dev.elmantrade.ru
www.integral.ru
admin.i-can-it.ru
taw.ru
test1.megaholod.ru
awsalon.ru
cab.your-domain.pro
alcartuma.ru
kru007.fix305.com
gitlit.ru
ru.courses.alexandr-andreev.ru
smartcollection.art
al-sheikh-khalil.net
hestia.loona-cafe.ru
mailb2b.auction.ru
srv.mega-stay.ru
admin.codepeckers.ru
adm-stage.dombilet.ru
kitay-mebel.ru
www.ivs-pdm.com
gitlab.insidenova.ru
yournumerology.ru
www.zao-proton.ru
openrace.by
victorymuseum.ru
lburo.ru
ant-book.ru
rdclr.ru
avistar.ru
alycoservis.ru
cloud.grando.pro
hasicistribro.familyds.net
preprod-auth.techcon.pro
git.unilight.ru
illidanbot.ru
www.meferi-id.ru
s19.wr0.ru
icult.ru
unitalk-app.934.su
al-ros.com
gitlab.splat.pro
dev.orchestrator.sherparpa.ru
basconi.su
drozd-sb.ru
poklonka-cinema.ru
bamlex.ru
crm.skidkabon.com
analytics.91-218-228-157.sslip.io
prikupit.by
crm.good-sisters.ru
mailform.izoom.digital
vopnbot.org
cover.playmuz.com
ila62.rushtaxi4.ru
unikadr.ru
demiurg.tv
fly-finance.ru
zulip.heado.ru
dom-san.ru
reshalka.com
www.tdk-opt.ru
api.fschool.su
afishakino.ru
xn-----6kcabbtgfdbdrnc4bej2bubbwfli1dyb5c9l8c.xn--p1ai
mail.kxxiv.ru
mludwik.myds.me
syastv.ru
fin-h2nexus.chickenkiller.com
ld.notfreeinetik.iiiii.info
hhkeittio.fi
alecseyyy.ru
vpnforppl.top
voyagertg.top
fi98.iiba.pw
frost.icephoenix.ru
mineboxes.com
h2n25end.uniun.site
dashboard.nothingchange.com
fin2h2.mymigrantik.online
hidefort.com
pink-service.ru
llloko.puttyssh.ru
f.449861.xyz
nex.fuflik.ru
hel03.userstorage.org
chibis.xyz
netbird.vaka.work
sup-mine.top
fi1.test.mytpn.net
finex.octanoq.store
pahan37.home.kg
ilovoonnl.strangled.net
atrium.144-31-5-246.sslip.io
pl.ninjaguru.digital
mail.work-access-solutions.com
j.sni-644-default.ssl.fastly.net
pl.npv-hosting.ru
pl5.moritech.net
panel.ultracomservice.com
github.com
pl6.moritech.net
ign.com
top-game-servers.com
rel-pl5.dotinfo.cfd
rel-pl2.dotinfo.cfd
hook.mysosa.xyz
edge-pl.mirrorgrid.net
impsave.com
batyavpn-tg.online
onenetwiki.top
m.sni-311-default.ssl.fastly.net
xepv.ru
pl1-pro.newservers.info
core.black-cat.app
n.sni-347-default.ssl.fastly.net
luxora-audio.com
rutube.ru
sub.yarche-public.mooo.com
fastload.info
catowndog-dns.duckdns.org
ai.raffles-systems.com
resetnet.ru
moneridge.com
pl-srv-03.fileforge.pw
pull.tifu.xyz
astroguard.wtf
dysfunction.gomodrilius.ru
static.nothingchange.com
1.hxiapp.cn
grafana.r00t4x.dev
nexus.my-handbook.ru
yahoo.com
plreverse.fastload.site
helionhq.link
pl-h-2.minzt.su
democrat.milkywash.com
cinema-city.pl
blook.pro
h2-pl.959105.xyz
wss2.nicklaus.ru
proxy.arivch.space
admin.greydance.ru
askay.unibutton.com
sub.anuu.ru
h2-100.mooo.com
tiltemitter.mooo.com
mesh-8012.spliceflowtech.com
dmitrolink.eclyra.org
shuval.site
cloudflare.com
pl3.moritech.net
blook.network
node510.ichost.cloud
muvluv.accesscam.org
bosfiles.net
notification-my-goglemail.com
rw.clearorbitllc.com
srv10171.epyc.fastwebserver.de
sub.api-fin-service.site
my.shootsell.com
speedload.online
potent.tuzvpn.com
sub.qpyyou.compuinter.com
msc.zzmm.ru
is2.zzmm.ru
node-dewb.slaywway.site
cloudcore.spktr.tech
panel.tokervpn.ru
ge-2.vpnezid.ru
www.cloudflare.com
api.flamebot.app
vps.litye-metall.ru
app.pegasus-vpn.shop
kirian.su
dev-s3.yanima.space
node241.ichost.cloud
salersvet.litye-metall.ru
web.liniya.me
subinstacheck.top
war.datakeep.ru
vps.zzmm.ru
api-email.eleximg.xyz
api.bypass.tools
ipgentech.cc
de-two.kanz1t.online
node102.ichost.cloud
origin2.dragonvpn.online
de1.pegas.world
gbox.iapps.sbs
origin-de.peak-tech.online
biohimltd.ru
xpnet.space
alana-arcana.ru
sub.dorblue.online
pl-h-1.minzt.su
scootie.nplug.digital
pln.nevex.pw
uiserver.site
pl-h2nexus.grani-gaming.shop
sub.kakashke.mooo.com
data-flow-365.net
pl.putinbox.eu
sub.alanbroken.mooo.com
dns.ruhub.dev
pl1.drinets0.ru
satir.tokervpn.ru
blays.tech
stream.zazavideo.org
tgbot.harknmav.fun
instaapi.sonyasqwirtik.com
pol145.univerkes.site
warsaw.ftp.sh
pol.danay.co
pl.kp7mx3.uk
sub.suckimrazi.iiiii.info
ingest-3.stratos-fn.com
www.kinjokdzr.com
vaultivo-hgooe.ru
itsmylivebaby.mooo.com
vovanpopka.mooo.com
fluxsolutions.ru
menu-test.toronto38.com
pl-srv-02.fileforge.pw
nu1.brut023.ru
huesosina.mooo.com
subahalaymahalay.mooo.com
nl1.programulsky.dpdns.org
email.kiberamlet.dev
pl.wequ.ickly.co.uk
sub.skouson.mysaol.com
sub.notavpn.iiiii.info
panel.xcix.online
szmk.mooo.com
144-31-14-16.cdn-one.org
ho.minusculus.ru
genshin.scalapups.tech
sub.mylovelykoza.chickenkiller.com
nl1.vline-secure.online
lg.play2go.cloud
vpn.144.31.14.44.nip.io
knock-knock.undo.it
epicgames.com
topten.ne-t.org
bosonsokk.hrrfkskllao.click
nl-ite-3.akumuvpn.ru
nl5gamehost.akhmatclub.ru
prod.bouncer.prod.webservices.mozgcp.net
144-31-14-171.cdn-one.org
hsosyb.hrrfkskllao.click
qppdyb.hrrfkskllao.click
api.evelynka.xyz
pux-nl.duckdns.org
www.swrg.ru
ltvconnect.ru
www.yandex.cloud
hachiware.site
144-31-14-207.cdn-one.org
multimediaholding.ru
nsubs.phantm.space
jurpass.com
ru13.netlighter.tech
teamboard.online
larix-gmelinii.ru
host3.education2026.abrdns.com
site.slog-auto.ru
muromdx.online
panel.144-31-16-21.nip.io
katze-baka.dynv6.net
tailscalesrv.work.gd
secureload.top
highlander-admin-panel.duckdns.org
e-mail.findify.nl
cloversolo.xyz
remnantglow.com
dimsen.strangled.net
fk.bubki.zip
xui.slesch.fun
null-core.com
144.31.16.153.nip.io
b.meskry1234.bond
catspictures.space
animeow.teeworlds.qzz.io
dota2.csproject.org
core.ipzxc.ru
s.binnor.ru
tlgx.twilightparadox.com
mobmedia.pro
workfine.space
goblin.geno.su
gallery.justducks.ru
craneits.ignorelist.com
altwaytwogg.my-cdn.host
sg4.vip-bloggers.site
sanchez.digital-streamline.ru
riverme49.ru
athena.dealeyra.dedyn.io
socleentorig.roflvpn.ru
144-31-17-113.cdn-one.org
z.tickethive.ru
images.apple.com
vm680520.abrdns.com
twitch.tv
usequoia.com
pke-buy.com
system.work.gd
travel.yandex.ru
confluence.skybitcore.com
sync.scarletclub.cc
www.sap.com
playersworld.fun
media.hochuv2005.xyz
pizdukcctv.duckdns.org
kaif.baixo.ru
dx-lib-cache.online
special57.baselinux.net
www.petrovskymost.com
177603.senko.network
rocky-linux-africa-south1.production.gcp.mirrors.ctrliq.cloud
studiotech.ru
citizenlab.ca
wow.truthpre.com
dns.hm8.ru
helsinki.fi
only.my.to
tf2key.com
loton.app
abo2025.valudata.fi
finland.msa-net.xyz
isp2fin.mworx.net
senko.spbmost.ru
debug.uttech.site
www.helsinki.fi
www.avito.st
glaz.katamnez.ru
aa.zwer666.abrdns.com
jstor.org
www.speedtest.net
fn2.skydrgn-online.online
comment-out.xyz
git.snop.agency
redmachine.servegame.com
web.livewave.ru
fi02-partition.corefield.xyz
xetag.chickenkiller.com
panel.citr0n.space
niberlandz1.kovsh.lol
grmeh-ast.ru
nl2.panel.cleanersaz.help
pressable.com
sub.blxmesa.ignorelist.com
rus-files.online
vrdx.pro
host.education2026.abrdns.com
2-26-92-137.cdn-one.org
xorq.net
latmeridian.com
audi.zerocool.pw
hel.x-custom.ru
slovary.pro
default.x5.ru
crm.ipstore-rnd.ru
slideweb.info
fin1.jijiconvert.online
no-sni.vercel-infra.com
netherlands.unblockvps.ru
standart.click-connect.online
www.market.yandex.ru
vector-vpn.com
vxe.su
graduationife.beer
virusite.online
auth.quillbin.com
telia.se
fi.zerobond.dedyn.io
user212.rise-tech.uk
beget.com
panel.gamestoria.ru
nekopass.ru
pavel-roz.duckdns.org
se.sni-one-dns.ru
kitty.bbapp.ru
tor.source.kernel.org
sousou.love-frieren.com
matrix-admin.rwbcode.com
tunnelpanel.com
mws-serv.temik.fun
employers.samplejobs.com
finland.fi
cms.stage.ar.sweden.se
wordpress.com
car-phuket.online
swed1.host.tauworld.space
aidoors2.xepbigboobs.fun
fi8.ai-woow.ru
edstore.app
ns2.gcb-v.ru
s12.bsh-net.ru
origin.safunches.site
sw.rudayz.ru
swe.office-l27.com
heavyindustry.duckdns.org
work.rettro.abrdns.com
asiaestate.ru
blocket.se

# --- wildcard-сертификаты из лога (в самом конце, закомментированы) --------
# Для SNI нужно точное имя хоста, а '*.example.com' сертификатом не является
# именем хоста. Реальные поддомены за звёздочкой определить не удалось,
# поэтому они НЕ добавлены в проверку. Если знаете живой поддомен —
# раскомментируйте строку и подставьте его вместо '*'.
# *.1c.ru
# *.1pei.me
# *.111500.xyz
# *.a.trbcdn.net
# *.ansa.it
# *.api.dropplite.com
# *.app.dropbox.com
# *.avatars.yandex.net
# *.avito.ru
# *.b-cdn.net
# *.b4com.tech
# *.bcriva.ru
# *.behance.net
# *.cdn.ngenix.net
# *.cdnvideo.ru
# *.cloudbird.top
# *.convert-flow.net
# *.crm.gazelk.in
# *.dedpi.com
# *.dualizm.space
# *.edgecdn.world
# *.ekagroup.ru
# *.envytool.ru
# *.even.games.s3.yandex.net
# *.fedoraproject.org
# *.framer.app
# *.hr-bigband.de
# *.igoratour.ru
# *.max.ru
# *.meto.club
# *.mosoblgaz.ru
# *.muztrade.com
# *.mycatscollection.com
# *.mycdn.me
# *.nebusfinance.ru
# *.neumo.ru
# *.niipp.ru
# *.nsburo.ru
# *.ozon.ru
# *.petrovich.ru
# *.pickpoint.io
# *.posterix.pro
# *.price-truck.ru
# *.pt-reply.com
# *.rakurs-cdn.com
# *.rakurs-cdn.org
# *.reddit.com
# *.redsms.ru
# *.reply.it
# *.ritm.uz
# *.rnrc.ru
# *.rt-capital.ru
# *.selcdn.ru
# *.spotifycdn.com
# *.subinstacheck.top
# *.tass.ru
# *.telegram.org
# *.userapi.com
# *.vascorp.ru
# *.vk.com
# *.vlessit.com
# *.vpn.partners
# *.vpntype.dev
# *.vseinstrumenti.ru
# *.whypay.info
# *.wp.pl
# *.www.yahoo.com
# *.x5.ru
# *.x5club.run
# *.x5media.ru
# *.yandex.tr
# *.yccdn.cloud.yandex.net
SNI_LIST
}

# источник списка: файл из -f или встроенный список
list_source() {
	if [[ -n "$FILE" ]]; then
		cat -- "$FILE"
	else
		builtin_list
	fi
}

usage() {
	cat <<'EOF'
sni-scan.sh — перебор SNI для VLESS-сервера (Reality / TLS + Vision)

ИСПОЛЬЗОВАНИЕ
  ./sni-scan.sh -i <IP-сервера> [-p 443] [-f <файл-со-SNI>] [опции]

ОБЯЗАТЕЛЬНЫЕ КЛЮЧИ
  -i, --ip ADDR       IP (или хост) вашего VLESS-сервера

СПИСОК SNI
  -f, --file PATH     файл со списком доменов-кандидатов: по одному в строке,
                      "#" — комментарий; https://, :порт, /путь, "*." срезаются
                      без -f берётся встроенный список (см. --print-list)
      --print-list    вывести встроенный список и выйти

ОПЦИИ
  -p, --port N        TLS-порт сервера                      (по умолчанию 443)
  -t, --timeout SEC   таймаут одной попытки                                (5)
  -j, --jobs N        сколько проверок параллельно                        (16)
  -o, --out PATH      имя файла отчёта; по умолчанию имя генерится само:
                      sni-scan_<IP>_<порт>_<ГГГГ-ММ-ДД_ЧЧ-ММ-СС>.tsv
      --no-out        не сохранять отчёт в файл
  -a, --alpn LIST     ALPN-список, "" — не отправлять            (h2,http/1.1)
  -n, --top N         сколько лучших показать в итоге; 0 — все GOOD/OK   (0)
  -g, --only-good     в процессе печатать только GOOD/OK
      --any-tls       не требовать TLS 1.3 (по умолчанию хендшейк -tls1_3)
      --http          доп. проверка: отдаёт ли сервер HTTP-ответ (медленнее)
      --http-wait SEC сколько ждать HTTP-ответ                            (1)
      --need-dns      пропускать домены, которые не резолвятся
      --no-baseline   не делать контрольный запрос со случайным SNI
      --no-color      без цвета
  -h, --help          справка
  -V, --version       версия

ПРИМЕРЫ
  ./sni-scan.sh -i 203.0.113.10                  # встроенный список + отчёт
  ./sni-scan.sh -i 203.0.113.10 -j 32            # быстрее: 32 проверки параллельно
  ./sni-scan.sh -i 203.0.113.10 -n 20            # в итоге только топ-20
  ./sni-scan.sh -i 203.0.113.10 -g               # в процессе печатать только удачные
  ./sni-scan.sh -i vps.example.net -f sni.txt --http --need-dns -o all.tsv
  ./sni-scan.sh -i 203.0.113.10 --any-tls -a ''  # самый мягкий режим
  ./sni-scan.sh -i 203.0.113.10 --no-out         # не писать файл отчёта

ВЕРДИКТЫ
  GOOD  хендшейк ок, TLS 1.3, сертификат валиден И выдан на этот же домен
        (обычно ещё X25519 + h2) — лучший кандидат для sni/serverName
  OK    хендшейк ок, TLS 1.3, но сертификат на другое имя / не проверился
  WEAK  соединение есть, но TLS ниже 1.3 либо сертификата нет
  FAIL  не подключилось: timeout / refused / TLS alert

ПРО REALITY (важно)
  Reality-сервер проксирует чужой (не своего клиента) TLS-хендшейк на свой dest,
  поэтому контрольный запрос со случайным SNI показывает сертификат именно dest.
  Имена из этого сертификата (CN и SAN) — и есть то, что надо ставить в sni /
  serverName на клиенте и в serverNames на сервере. Хороший кандидат:
  TLS 1.3 + X25519 + h2 + verify=ok.

Скрипт просто делает TLS-хендшейк к тому серверу, который вы указали.
Предназначен для диагностики своих серверов.
EOF
}

need_val() {
	[[ $# -ge 2 && -n "${2:-}" ]] || {
		echo "Ошибка: у ключа $1 нет значения" >&2
		exit 2
	}
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--print-list)
		builtin_list
		exit 0
		;;
	-f | --file)
		need_val "$@"
		FILE="$2"
		shift 2
		;;
	-i | --ip | --host)
		need_val "$@"
		HOSTIP="$2"
		shift 2
		;;
	-p | --port)
		need_val "$@"
		PORT="$2"
		shift 2
		;;
	-t | --timeout)
		need_val "$@"
		TMO="$2"
		shift 2
		;;
	-j | --jobs)
		need_val "$@"
		JOBS="$2"
		shift 2
		;;
	-o | --out | --output)
		need_val "$@"
		OUT="$2"
		shift 2
		;;
	--no-out)
		NO_OUT=1
		shift
		;;
	-a | --alpn)
		ALPN="${2:-}"
		shift 2
		;;
	-n | --top)
		need_val "$@"
		TOPN="$2"
		shift 2
		;;
	-g | --only-good)
		ONLY_GOOD=1
		shift
		;;
	--any-tls)
		ANY_TLS=1
		shift
		;;
	--http)
		DO_HTTP=1
		shift
		;;
	--no-http)
		DO_HTTP=0
		shift
		;;
	--http-wait)
		need_val "$@"
		HTTP_WAIT="$2"
		DO_HTTP=1
		shift 2
		;;
	--need-dns)
		NEED_DNS=1
		shift
		;;
	--no-baseline)
		NO_BASELINE=1
		shift
		;;
	--no-color)
		NOCOLOR=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	-V | --version)
		echo "sni-scan.sh $VERSION"
		exit 0
		;;
	--_probe) # внутренний режим: одна проверка, вывод одной TSV-строкой
		need_val "$@"
		MODE="probe"
		PROBE_SNI="$2"
		shift 2
		;;
	*)
		echo "Неизвестный ключ: $1" >&2
		echo "Справка: $0 --help" >&2
		exit 2
		;;
	esac
done

# ---------------------------------------------------------------- цвета ------
if [[ "$NOCOLOR" == "1" || ! -t 1 ]]; then
	C_R="" C_G="" C_Y="" C_B="" C_D="" C_0=""
else
	C_R=$'\033[31m' C_G=$'\033[32m' C_Y=$'\033[33m' C_B=$'\033[36m' C_D=$'\033[2m' C_0=$'\033[0m'
fi

die() {
	echo "${C_R}Ошибка:${C_0} $*" >&2
	exit 1
}

command -v openssl >/dev/null 2>&1 || die "не найден openssl (установи: apt install openssl / dnf install openssl)"
TIMEOUT_BIN="$(command -v timeout || true)"

run_tmo() {
	if [[ -n "$TIMEOUT_BIN" ]]; then "$TIMEOUT_BIN" -k 1 "$TMO" "$@"; else "$@"; fi
}

now_ms() {
	local n
	n="$(date +%s%N 2>/dev/null)"
	if [[ -z "$n" || "$n" == *N* ]]; then echo $(($(date +%s) * 1000)); else echo $((n / 1000000)); fi
}

short() { # short <строка> <макс-длина>
	local s="${1:--}" n="$2"
	[[ -z "$s" ]] && s="-"
	if ((${#s} > n)); then echo "${s:0:n-1}~"; else echo "$s"; fi
}

verify_txt() { # код openssl -> человеческое объяснение
	case "${1%% *}" in
	"") echo "-" ;;
	0) echo "ok" ;;
	10) echo "expired" ;;
	18 | 19) echo "self-signed" ;;
	20 | 21) echo "no-chain" ;;
	62) echo "name-mismatch" ;;
	*) echo "code=${1%% *}" ;;
	esac
}

# ============================== одна проверка ================================
probe_one() {
	local sni="$1"

	local -a args=(-connect "$HOSTIP:$PORT" -servername "$sni" -verify_hostname "$sni" -verify 5)
	[[ -n "$ALPN" ]] && args+=(-alpn "$ALPN")
	[[ "$ANY_TLS" == "1" ]] || args+=(-tls1_3)

	# --- фаза 1: только хендшейк (быстро, сразу закрываем соединение) ---
	local raw rc t0 t1 ms
	t0="$(now_ms)"
	raw="$(run_tmo openssl s_client "${args[@]}" </dev/null 2>&1)"
	rc=$?
	t1="$(now_ms)"
	ms=$((t1 - t0))

	local tls cipher alpn_neg tempkey verify cn http reason verdict score
	tls="$(sed -n -E 's/^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*//p' <<<"$raw" | head -1)"
	[[ -z "$tls" ]] && tls="$(grep -o 'New, TLSv[0-9.]*' <<<"$raw" | head -1 | sed 's/New, //')"
	cipher="$(sed -n -E 's/.*Cipher is ([^ ]+).*/\1/p' <<<"$raw" | head -1)"
	[[ -z "$cipher" ]] && cipher="$(sed -n -E 's/^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*//p' <<<"$raw" | head -1)"
	alpn_neg="$(sed -n -E 's/^ALPN protocol: //p' <<<"$raw" | head -1)"
	[[ -z "$alpn_neg" ]] && alpn_neg="-"
	# openssl 1.1.1 пишет "Server Temp Key", openssl 3.x — "Peer Temp Key"
	tempkey="$(sed -n -E 's/^(Server|Peer) Temp Key: //p' <<<"$raw" | head -1)"
	[[ -z "$tempkey" ]] && tempkey="-"
	verify="$(sed -n -E 's/^[[:space:]]*Verify return code:[[:space:]]*//p' <<<"$raw" | head -1)"
	cn="$(sed -n -E 's/^subject=.*CN[[:space:]]*=[[:space:]]*//p' <<<"$raw" | head -1)"
	[[ -z "$cn" ]] && cn="$(sed -n -E 's/^depth=0 .*CN[[:space:]]*=[[:space:]]*//p' <<<"$raw" | head -1)"
	http="-"
	reason=""

	if [[ -z "$tls" || "$tls" == "0000" ]]; then
		# ------------------------- разбор причины неудачи -------------------
		verdict="FAIL"
		score=0
		if [[ "$rc" == "124" || "$rc" == "137" ]]; then
			reason="timeout ${TMO}s"
		elif grep -qi 'connection refused' <<<"$raw"; then
			reason="connection refused"
		elif grep -qi 'connection reset\|reset by peer' <<<"$raw"; then
			reason="connection reset"
		elif grep -qi 'name or service not known\|nodename nor servname\|temporary failure in name' <<<"$raw"; then
			reason="dns/host error"
		elif grep -qi 'no protocols available\|unsupported protocol\|wrong version number' <<<"$raw"; then
			reason="нет TLS 1.3 (попробуй --any-tls)"
		elif grep -qi 'no application protocol' <<<"$raw"; then
			reason="ALPN отклонён (попробуй -a '' или -a http/1.1)"
		elif grep -qi 'unrecognized name' <<<"$raw"; then
			reason="SNI отклонён сервером (unrecognized_name)"
		elif grep -qi 'alert' <<<"$raw"; then
			reason="TLS alert: $(grep -o -i -m1 'alert [a-z_ ]*' <<<"$raw" | head -1 | cut -c1-40)"
		else
			reason="$(grep -m1 -i 'error\|errno\|refused' <<<"$raw" | sed -E 's/^[[:space:]]+//' | cut -c1-60)"
			[[ -z "$reason" ]] && reason="хендшейк не состоялся (rc=$rc)"
		fi
	else
		# --- фаза 2 (по желанию): отвечает ли сервер на HTTP-запрос ---
		# Отдельное соединение с ALPN http/1.1 (по h2 текстовый запрос не пройдёт).
		# stdin держим открытым ровно HTTP_WAIT секунд — чтоб успеть считать ответ.
		if [[ "$DO_HTTP" == "1" ]]; then
			local -a hargs=(-connect "$HOSTIP:$PORT" -servername "$sni" -alpn http/1.1 -quiet)
			[[ "$ANY_TLS" == "1" ]] || hargs+=(-tls1_3)
			local hraw
			hraw="$({
				printf 'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n' "$sni"
				sleep "$HTTP_WAIT"
			} | run_tmo openssl s_client "${hargs[@]}" 2>&1)"
			http="$(grep -m1 -o -E 'HTTP/[0-9.]+ [0-9]{3}' <<<"$hraw" | awk '{print $2}')"
			[[ -z "$http" ]] && http="-"
		fi

		# ------------------------------- оценка ----------------------------------
		score=2
		[[ "$tls" == "TLSv1.3" ]] && score=$((score + 3))
		[[ "${verify%% *}" == "0" ]] && score=$((score + 3))
		[[ "$tempkey" == X25519* ]] && score=$((score + 1))
		[[ "$alpn_neg" == "h2" ]] && score=$((score + 1))
		[[ "$http" != "-" ]] && score=$((score + 1))

		if [[ "$tls" == "TLSv1.3" && "${verify%% *}" == "0" ]]; then
			verdict="GOOD"
		elif [[ "$tls" == "TLSv1.3" ]]; then
			verdict="OK"
		else
			verdict="WEAK"
		fi
		if [[ -z "$cn" ]]; then
			verdict="WEAK"
			reason="без сертификата"
		fi
		[[ -z "$reason" ]] && reason="$(verify_txt "$verify")"
	fi

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$verdict" "$score" "$ms" "$sni" "${tls:--}" "${cipher:--}" "$alpn_neg" \
		"$tempkey" "$(verify_txt "$verify")" "$http" "${cn:--}" "${reason:--}"
}

if [[ "$MODE" == "probe" ]]; then
	probe_one "$PROBE_SNI"
	exit 0
fi

# ================================== main =====================================
[[ -z "$FILE" || -r "$FILE" ]] || die "файл '$FILE' не найден или не читается"
[[ -n "$HOSTIP" ]] || {
	usage >&2
	echo >&2
	die "не указан адрес сервера (-i/--ip)"
}
[[ "$PORT" =~ ^[0-9]+$ ]] || die "порт должен быть числом (получено: '$PORT')"
[[ "$JOBS" =~ ^[0-9]+$ && "$JOBS" -gt 0 ]] || die "-j должно быть числом > 0"
[[ "$TOPN" =~ ^[0-9]+$ ]] || die "-n должно быть числом >= 0 (0 — показать все прошедшие)"

# Отчёт пишется всегда: имя = цель + дата/время запуска.
# Своё имя — ключом -o, отключить совсем — ключом --no-out.
if [[ -z "$OUT" && "$NO_OUT" != "1" ]]; then
	OUT="sni-scan_${HOSTIP//[^0-9A-Za-z.-]/_}_${PORT}_$(date +%Y-%m-%d_%H-%M-%S).tsv"
fi

print_row() { # вердикт score ms sni tls cipher alpn tempkey verify http cn reason
	local color info
	case "$1" in
	GOOD) color="$C_G" ;;
	OK) color="$C_B" ;;
	WEAK) color="$C_Y" ;;
	*) color="$C_R" ;;
	esac
	if [[ "$1" == "FAIL" ]]; then
		info="${12}"
	else
		info="cert:$(short "${11}" 28) [${9}]"
	fi
	printf "%s%-4s%s %-30s %-6s %-9s %-8s %-5s %6s %s\n" \
		"$color" "$1" "$C_0" "$(short "$4" 30)" "${5#TLS}" "$(short "${8%%,*}" 9)" \
		"${7}" "${10}" "${3}ms" "$info"
}

hdr() {
	printf "${C_D}%-4s %-30s %-6s %-9s %-8s %-5s %6s %s${C_0}\n" \
		"итог" "SNI" "TLS" "KEX" "ALPN" "HTTP" "время" "детали"
}

# ------------------------------------------------- чтение списка кандидатов --
# чистим: CRLF, комментарии, пробелы, схему, путь, порт, "*.", точку в конце, регистр
if [[ -n "$FILE" ]]; then
	SRC_LABEL="файл $FILE"
else
	SRC_LABEL="встроенный список"
fi

mapfile -t RAWLIST < <(
	list_source |
		tr -d '\r' |
		sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' |
		sed -E -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' -e 's#/.*$##' -e 's/:[0-9]+$//' \
			-e 's/^\*\.//' -e 's/\.$//' |
		tr 'A-Z' 'a-z' |
		awk 'NF && !seen[$0]++'
)

CANDS=()
SKIPPED=0
for h in "${RAWLIST[@]}"; do
	if [[ "$h" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$h" == *.* ]]; then
		if [[ "$NEED_DNS" == "1" ]] && ! getent hosts "$h" >/dev/null 2>&1; then
			SKIPPED=$((SKIPPED + 1))
			continue
		fi
		CANDS+=("$h")
	else
		SKIPPED=$((SKIPPED + 1))
	fi
done

TOTAL="${#CANDS[@]}"
((TOTAL > 0)) || die "в источнике ($SRC_LABEL) не нашлось ни одного валидного домена"

echo
echo "${C_B}==> sni-scan $VERSION${C_0}  цель: ${HOSTIP}:${PORT}   кандидатов: ${TOTAL}$([[ $SKIPPED -gt 0 ]] && echo " (пропущено: $SKIPPED)")"
echo "    таймаут ${TMO}s | потоков ${JOBS} | ALPN '${ALPN:-нет}' | TLS $([[ "$ANY_TLS" == "1" ]] && echo "любой" || echo "только 1.3")$([[ "$DO_HTTP" == "1" ]] && echo " | +HTTP")"
echo "    источник списка: ${SRC_LABEL}"

# ------------------------------------------- контрольный запрос (baseline) ---
if [[ "$NO_BASELINE" != "1" ]]; then
	RND="$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 12).com"
	echo
	echo "${C_B}--- контроль: случайный SNI (${RND}) ---${C_0}"
	BASE_RAW="$(run_tmo openssl s_client -connect "$HOSTIP:$PORT" -servername "$RND" \
		${ALPN:+-alpn "$ALPN"} -showcerts </dev/null 2>&1)"
	BASE_PEM="$(awk '/-BEGIN CERTIFICATE-/{f=1} f{print} /-END CERTIFICATE-/{if(f) exit}' <<<"$BASE_RAW")"
	BASE_TLS="$(sed -n -E 's/^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*//p' <<<"$BASE_RAW" | head -1)"
	BASE_ALPN="$(sed -n -E 's/^ALPN protocol: //p' <<<"$BASE_RAW" | head -1)"
	BASE_KEX="$(sed -n -E 's/^(Server|Peer) Temp Key: //p' <<<"$BASE_RAW" | head -1)"
	if [[ -n "$BASE_PEM" ]]; then
		BASE_SUBJ="$(openssl x509 -noout -subject <<<"$BASE_PEM" 2>/dev/null | sed -E 's/^subject=[[:space:]]*//')"
		BASE_ISS="$(openssl x509 -noout -issuer <<<"$BASE_PEM" 2>/dev/null | sed -E 's/^issuer=[[:space:]]*//')"
		BASE_SAN="$(openssl x509 -noout -ext subjectAltName <<<"$BASE_PEM" 2>/dev/null |
			tr -d ' ' | tr ',' '\n' | sed -n 's/^DNS://p' | paste -sd, -)"
		if [[ -z "$BASE_SAN" ]]; then
			BASE_SAN="$(openssl x509 -noout -text <<<"$BASE_PEM" 2>/dev/null |
				grep -A1 'Subject Alternative Name' | tail -1 | tr -d ' ' | tr ',' '\n' |
				sed -n 's/^DNS://p' | paste -sd, -)"
		fi
		echo "  TLS/KEX/ALPN : ${BASE_TLS:-—} | ${BASE_KEX:-—} | ${BASE_ALPN:-—}"
		echo "  subject      : ${BASE_SUBJ:-—}"
		echo "  issuer       : ${BASE_ISS:-—}"
		echo "  SAN          : ${BASE_SAN:--}"
		echo "  ${C_G}Подсказка:${C_0} сервер отдаёт этот сертификат даже на случайный SNI."
		echo "  У Reality это сертификат его dest — имена выше (CN/SAN) и есть главные"
		echo "  кандидаты в sni/serverName. Добавь их в список и проверь перебором."
	else
		echo "  сертификат не получен: $(grep -m1 -i 'error\|alert\|refused\|timeout' <<<"$BASE_RAW" | sed -E 's/^[[:space:]]+//' | cut -c1-70)"
		echo "  ${C_D}значит сервер фильтрует SNI (или порт закрыт) — перебор ниже покажет${C_0}"
	fi
fi

# ------------------------------------------------------------- сам перебор ---
RAW_RES="$(mktemp -t sniscan.XXXXXX)"
trap 'rm -f "$RAW_RES"' EXIT

export SNIS_IP="$HOSTIP" SNIS_PORT="$PORT" SNIS_TIMEOUT="$TMO" SNIS_ALPN="$ALPN" \
	SNIS_ANY_TLS="$ANY_TLS" SNIS_DO_HTTP="$DO_HTTP" SNIS_HTTP_WAIT="$HTTP_WAIT" SNIS_NOCOLOR=1

echo
[[ -n "$OUT" ]] && echo "${C_D}отчёт будет сохранён в ${OUT}${C_0}"
echo "${C_B}--- перебор (${TOTAL}) ---${C_0}"
hdr

printf '%s\n' "${CANDS[@]}" |
	xargs -P "$JOBS" -I '{}' "${BASH:-/bin/bash}" "$SELF" --_probe '{}' |
	tee "$RAW_RES" |
	while IFS=$'\t' read -r v sc ms sni tls ciph alpn tk vr ht cn rs; do
		[[ "$ONLY_GOOD" == "1" && "$v" != "GOOD" && "$v" != "OK" ]] && continue
		print_row "$v" "$sc" "$ms" "$sni" "$tls" "$ciph" "$alpn" "$tk" "$vr" "$ht" "$cn" "$rs"
	done

# ---------------------------------------------------------------- итоги ------
cnt() { awk -F'\t' -v v="$1" '$1==v' "$RAW_RES" | wc -l | tr -d ' '; }
n_good="$(cnt GOOD)"
n_ok="$(cnt OK)"
n_weak="$(cnt WEAK)"
n_fail="$(cnt FAIL)"

echo
echo "${C_B}--- итог ---${C_0}  GOOD: ${C_G}${n_good}${C_0} | OK: ${C_B}${n_ok}${C_0} | WEAK: ${C_Y}${n_weak}${C_0} | FAIL: ${C_R}${n_fail}${C_0} | всего: ${TOTAL}"

if ((n_good + n_ok > 0)); then
	echo
	if [[ "$TOPN" == "0" ]]; then
		LIMIT=(cat)
		echo "Все прошедшие ($((n_good + n_ok)), сначала самые подходящие и быстрые):"
	else
		LIMIT=(head -n "$TOPN")
		echo "Лучшие кандидаты (до ${TOPN} из $((n_good + n_ok)), сначала самые подходящие и быстрые):"
	fi
	hdr
	awk -F'\t' '$1=="GOOD" || $1=="OK"' "$RAW_RES" |
		sort -t$'\t' -k2,2nr -k3,3n |
		"${LIMIT[@]}" |
		while IFS=$'\t' read -r v sc ms sni tls ciph alpn tk vr ht cn rs; do
			print_row "$v" "$sc" "$ms" "$sni" "$tls" "$ciph" "$alpn" "$tk" "$vr" "$ht" "$cn" "$rs"
		done
	echo
	if [[ "$TOPN" != "0" ]] && ((n_good + n_ok > TOPN)); then
		echo "${C_Y}Показаны ${TOPN} из $((n_good + n_ok)) — чтобы увидеть все, добавь -n 0${C_0}"
		echo
	fi
	echo "${C_D}Бери SNI с вердиктом GOOD (TLS1.3 + X25519 + h2 + cert ok) и подставляй в клиент:${C_0}"
	echo "${C_D}  vless://<uuid>@${HOSTIP}:${PORT}?type=tcp&security=reality&sni=<SNI>&fp=chrome&pbk=<publicKey>&sid=<shortId>&flow=xtls-rprx-vision${C_0}"
	echo "${C_D}Для Reality это же имя должно быть в serverNames на сервере (и совпадать с dest).${C_0}"
else
	echo
	echo "${C_Y}Ни один SNI не прошёл.${C_0} Что попробовать:"
	echo "  • проверить, что порт вообще слушает:  nc -vz ${HOSTIP} ${PORT}"
	echo "  • увеличить таймаут и снизить параллельность:  -t 10 -j 4"
	echo "  • разрешить TLS ниже 1.3:  --any-tls"
	echo "  • убрать ALPN:  -a ''"
	echo "  • взять список пожирнее (домены с TLS 1.3 + h2 + X25519, без CDN-редиректов)"
fi

if [[ -n "$OUT" ]]; then
	{
		printf 'verdict\tscore\tms\tsni\ttls\tcipher\talpn\ttemp_key\tverify\thttp\tcert_cn\treason\n'
		sort -t$'\t' -k2,2nr -k3,3n "$RAW_RES"
	} >"$OUT" && echo && echo "${C_G}Отчёт сохранён:${C_0} $OUT  (все ${TOTAL} строк, 12 колонок)"
fi

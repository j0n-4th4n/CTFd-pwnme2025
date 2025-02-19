# Pixo Theme
Pixo is a Retro Styled Theme for CTFd which consists of numerous features like OLD CRT like flicker, Old school fonts and notification sound which gives the theme a 90s look.

Compatible with CTFd **Version 3.3.0**

Few Screenshots:
  
  ![Index Page](https://i.imgur.com/lL7zYrg.gif "Index Page")
  
  ![Challenge Page](https://i.imgur.com/o1XHK2t.png "Challenge Page")
  
  ![Challenge Popup](https://i.imgur.com/7YAQFs5.png "Challenge Popup")
  
  ![Score Board](https://i.imgur.com/COI4yAo.png "Score Board")
  
  ![Login Page](https://i.imgur.com/206O99m.png "Login Page")

<br>
<br>

### Installation Steps Before deployment:

## Step 1:
Go to `/CTFd/CTFd/themes` then 
```
git clone https://github.com/j0n-4th4n/pwnme2025.git 
```

## Step 2:
In `/CTFd/CTFd/views.py` at line ***208** copy past this code for variable `index`
```html
<style>
  /* Overall container with a retro parchment background */
  .retro-container {
    padding: 20px;
    margin: 20px 0;
    font-family: "Courier New", Courier, monospace;
  }

  p, li {
  	font-weight: bold;
  }

  /* Section headings with a purple gradient effect (lighter purple from top to bottom) */
  .section-heading {
    font-family: "Press Start 2P", cursive;
    text-align: center;
    margin-bottom: 15px;
    font-size: 1.5rem;
    background: linear-gradient(45deg, #281b9a, #3d24aa, #5947bc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: 1px 1px 0px rgba(0, 0, 0, 0.3);
  }

  .desc-heading {
    font-size: 1.6rem;
  }

  .quals-heading,
  .finals-heading,
  .location-heading,
  .contact-heading,
  .sponsors-heading,
  .prizes-heading {
    font-size: 1.4rem;
  }

  /* Section content styling */
  .section-content {
    text-align: center;
    padding: 10px 20px;
    margin-bottom: 20px;
    position: relative;
  }

  h4, h3 {
    position: relative;
    display: inline-block;
    text-align: center;
    opacity: 1;
  }

  h4:hover, h3:hover {
    text-shadow: 1px -1px #6a1b9a, -1px 1px #ab47bc;
  }

  h4::before, h3::before {
    content: attr(data-text);
    position: absolute;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    color: #e0ffff;
    width: 100%;
    height: 100%;
    mix-blend-mode: difference;
    transition: 0.1s ease-in-out;
    text-align: center;
  }

  h4:hover::before, h3:hover::before {
    animation: glitch 360ms ease-in-out infinite;
  }

  /* Further adjusted keyframes for an even softer glitch effect */
  @keyframes glitch {
    0% {
      top: 0;
      left: 50%;
      transform: translateX(-50%);
      opacity: 1;
    }
    20% {
      top: -0.5px;
      left: 49.5%;
    }
    40% {
      top: 0.5px;
      left: 50.5%;
    }
    60% {
      top: -0.25px;
      left: 50.25%;
    }
    80% {
      top: 0.25px;
      left: 49.75%;
    }
    100% {
      top: 0;
      left: 50%;
      transform: translateX(-50%);
      opacity: 1;
    }
  }

  /* Glitch effect class */
  .glitch-active {
    text-shadow: 2px -2px #6a1b9a, -2px 2px #ab47bc;
  }

  .glitch-active::before {
    content: attr(data-text);
    position: absolute;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    color: #e0ffff;
    width: 100%;
    height: 100%;
    mix-blend-mode: difference;
    animation: glitch 360ms ease-in-out infinite;
  }
</style>



<script>
  function triggerRandomGlitch() {
    // Select all h3 and h4 elements
    const headings = document.querySelectorAll("h3.section-heading, h4.section-heading");

    if (headings.length === 0) return; // Exit if no headings found

    // Pick a random heading
    const randomHeading = headings[Math.floor(Math.random() * headings.length)];

    // Add glitch effect class
    randomHeading.classList.add("glitch-active");

    // Remove effect after 2 seconds
    setTimeout(() => {
      randomHeading.classList.remove("glitch-active");
    }, 2000);
  }

  // Run the glitch effect every 5 seconds (adjust as needed)
  setInterval(triggerRandomGlitch, 5000);
</script>

  
  <div class="container retro-container">
    <div class="row">
      <div class="col-md-6 offset-md-3 text-center">
        <img
          class="w-100 mx-auto d-block"
          style="max-width: 500px; padding: 50px; padding-top: 14vh"
          src="/themes/CTFd-theme-pixo/static/img/PwnMe_Logo2025_BASIC.svg"
          alt="PWNME CTF Logo"
        />
      </div>
    </div>
    <div class="row">
      <div class="col-md-6 offset-md-3 section-content glitch">
        <h3  data-text="Description du CTF" class="section-heading desc-heading">Description du CTF</h3>
        <p>
          Participez à notre challenge de cybersécurité et testez vos compétences
          dans un environnement rétro et ludique.
        </p>
      </div>
    </div>
    <div class="row">
      <div class="col-md-6 offset-md-3 section-content glitch">
        <h4  data-text="Dates des Qualifications" class="section-heading quals-heading">Dates des Qualifications</h4>
        <ul class="list-unstyled text-center">
          <li><strong>Qualifications :</strong> 15 - 17 Mars 2025</li>
        </ul>
      </div>
    </div>
    <div class="row">
      <div class="col-md-6 offset-md-3 section-content glitch">
        <h4 data-text="Dates des Finales" class="section-heading finals-heading">Dates des Finales</h4>
        <ul class="list-unstyled text-center">
          <li><strong>Finales :</strong> 25 Mars 2025</li>
        </ul>
      </div>
    </div>
    <div class="row">
      <div class="col-md-6 offset-md-3 section-content glitch">
        <h4 data-text="Lieu" class="section-heading location-heading">Lieu</h4>
        <p class="text-center">
          12 bis Quai François Truffaut, 78180 Montigny-le-Bretonneux, France
        </p>
      </div>
    </div>
    <div class="row">
      <div class="col-md-6 offset-md-3 section-content glitch">
        <h4 data-text="Informations de Contact" class="section-heading contact-heading">Informations de Contact</h4>
        <p class="text-center">
          Email : <a href="mailto:contact@ctfxyz.com">contact@ctfxyz.com</a>
        </p>
      </div>
    </div>
    <div class="row">
      <div class="col-md-6 offset-md-3 section-content glitch">
        <h4 data-text="Sponsors" class="section-heading sponsors-heading">Sponsors</h4>
        <p class="text-center">
          Merci à nos sponsors : <strong>CyberSec Corp, HackLab</strong>
        </p>
      </div>
    </div>
    <div class="row">
      <div class="col-md-6 offset-md-3 section-content glitch">
        <h4 data-text="Prix" class="section-heading prizes-heading">Prix</h4>
        <ul class="list-unstyled text-center">
          <li>🥇 1ère place : 5000€</li>
          <li>🥈 2ème place : 3000€</li>
          <li>🥉 3ème place : 1000€</li>
        </ul>
      </div>
    </div>
    <div class="row">
      <div class="col-md-6 offset-md-3 section-content glitch">
        <h4 data-text="Suivez-nous" class="section-heading">Suivez-nous</h4>
        <div class="social-icons text-center">
          <a href="https://twitter.com/ctfxyz"
            ><i class="fab fa-twitter fa-2x"></i></a
          ><a href="https://facebook.com/ctfxyz"
            ><i class="fab fa-facebook fa-2x"></i></a
          ><a href="https://github.com/ctfxyz"
            ><i class="fab fa-github fa-2x"></i
          ></a>
        </div>
      </div>
    </div>
  </div>
```
In order to get the page stored in the database, the latter will allow you to modify it as you wish

<br>
<br>

### Installation Steps After deployment:
Open your Docker container's terminal then insert the following Command:
```
git clone https://github.com/j0n-4th4n/pwnme2025.git /opt/CTFd/CTFd/themes/pwnme2025
```
Then Login as Admin and go to: ```Admin Panel > Config > Themes``` and switch the Theme to pixo and Click on Update.

That's it! Now you are good to goo..

<br>
<br>

## Custom License
1. User may edit the item, but can't replace My Theme Copyright & CTFd Copyright.
1. User need confirmation with us before removing copyright mark (footer).


<br>
<br>

## Credits
- [Freepik](https://www.freepik.com "Freepik") For their awesome images (Arrow & Coin).
- [CTFd](https://github.com/CTFd "CTFd") For Creating such an Awesome Platform.
 

import os  # noqa: I001

from flask import Blueprint, abort
from flask import current_app as app
from flask import (
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from jinja2.exceptions import TemplateNotFound
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import safe_join

from CTFd.cache import cache
from CTFd.constants.config import (
    AccountVisibilityTypes,
    ChallengeVisibilityTypes,
    ConfigTypes,
    RegistrationVisibilityTypes,
    ScoreVisibilityTypes,
)
from CTFd.constants.themes import DEFAULT_THEME
from CTFd.models import (
    Admins,
    Files,
    Notifications,
    Pages,
    Teams,
    Users,
    UserTokens,
    db,
)
from CTFd.utils import config, get_config, set_config
from CTFd.utils import user as current_user
from CTFd.utils import validators
from CTFd.utils.config import is_setup, is_teams_mode
from CTFd.utils.config.pages import build_markdown, get_page
from CTFd.utils.config.visibility import challenges_visible
from CTFd.utils.dates import ctf_ended, ctftime, view_after_ctf
from CTFd.utils.decorators import authed_only
from CTFd.utils.email import (
    DEFAULT_PASSWORD_RESET_BODY,
    DEFAULT_PASSWORD_RESET_SUBJECT,
    DEFAULT_SUCCESSFUL_REGISTRATION_EMAIL_BODY,
    DEFAULT_SUCCESSFUL_REGISTRATION_EMAIL_SUBJECT,
    DEFAULT_USER_CREATION_EMAIL_BODY,
    DEFAULT_USER_CREATION_EMAIL_SUBJECT,
    DEFAULT_VERIFICATION_EMAIL_BODY,
    DEFAULT_VERIFICATION_EMAIL_SUBJECT,
)
from CTFd.utils.health import check_config, check_database
from CTFd.utils.helpers import get_errors, get_infos, markup
from CTFd.utils.modes import USERS_MODE
from CTFd.utils.security.auth import login_user
from CTFd.utils.security.csrf import generate_nonce
from CTFd.utils.security.signing import (
    BadSignature,
    BadTimeSignature,
    SignatureExpired,
    serialize,
    unserialize,
)
from CTFd.utils.uploads import get_uploader, upload_file
from CTFd.utils.user import authed, get_current_team, get_current_user, get_ip, is_admin

views = Blueprint("views", __name__)


@views.route("/setup", methods=["GET", "POST"])
def setup():
    errors = get_errors()
    if not config.is_setup():
        if not session.get("nonce"):
            session["nonce"] = generate_nonce()
        if request.method == "POST":
            # General
            ctf_name = request.form.get("ctf_name")
            ctf_description = request.form.get("ctf_description")
            user_mode = request.form.get("user_mode", USERS_MODE)
            set_config("ctf_name", ctf_name)
            set_config("ctf_description", ctf_description)
            set_config("user_mode", user_mode)

            # Settings
            challenge_visibility = ChallengeVisibilityTypes(
                request.form.get(
                    "challenge_visibility", default=ChallengeVisibilityTypes.PRIVATE
                )
            )
            account_visibility = AccountVisibilityTypes(
                request.form.get(
                    "account_visibility", default=AccountVisibilityTypes.PUBLIC
                )
            )
            score_visibility = ScoreVisibilityTypes(
                request.form.get(
                    "score_visibility", default=ScoreVisibilityTypes.PUBLIC
                )
            )
            registration_visibility = RegistrationVisibilityTypes(
                request.form.get(
                    "registration_visibility",
                    default=RegistrationVisibilityTypes.PUBLIC,
                )
            )
            verify_emails = request.form.get("verify_emails")
            team_size = request.form.get("team_size")

            # Style
            ctf_logo = request.files.get("ctf_logo")
            if ctf_logo:
                f = upload_file(file=ctf_logo)
                set_config("ctf_logo", f.location)

            ctf_small_icon = request.files.get("ctf_small_icon")
            if ctf_small_icon:
                f = upload_file(file=ctf_small_icon)
                set_config("ctf_small_icon", f.location)

            theme = request.form.get("ctf_theme", DEFAULT_THEME)
            set_config("ctf_theme", theme)
            theme_color = request.form.get("theme_color")
            theme_header = get_config("theme_header")
            if theme_color and bool(theme_header) is False:
                # Uses {{ and }} to insert curly braces while using the format method
                css = (
                    '<style id="theme-color">\n'
                    ":root {{--theme-color: {theme_color};}}\n"
                    ".navbar{{background-color: var(--theme-color) !important;}}\n"
                    ".jumbotron{{background-color: var(--theme-color) !important;}}\n"
                    "</style>\n"
                ).format(theme_color=theme_color)
                set_config("theme_header", css)

            # DateTime
            start = request.form.get("start")
            end = request.form.get("end")
            set_config("start", start)
            set_config("end", end)
            set_config("freeze", None)

            # Administration
            name = request.form["name"]
            email = request.form["email"]
            password = request.form["password"]

            name_len = len(name) == 0
            names = (
                Users.query.add_columns(Users.name, Users.id)
                .filter_by(name=name)
                .first()
            )
            emails = (
                Users.query.add_columns(Users.email, Users.id)
                .filter_by(email=email)
                .first()
            )
            pass_short = len(password) == 0
            pass_long = len(password) > 128
            valid_email = validators.validate_email(request.form["email"])
            team_name_email_check = validators.validate_email(name)

            if not valid_email:
                errors.append("Please enter a valid email address")
            if names:
                errors.append("That user name is already taken")
            if team_name_email_check is True:
                errors.append("Your user name cannot be an email address")
            if emails:
                errors.append("That email has already been used")
            if pass_short:
                errors.append("Pick a longer password")
            if pass_long:
                errors.append("Pick a shorter password")
            if name_len:
                errors.append("Pick a longer user name")

            if len(errors) > 0:
                return render_template(
                    "setup.html",
                    errors=errors,
                    name=name,
                    email=email,
                    password=password,
                    state=serialize(generate_nonce()),
                )

            admin = Admins(
                name=name, email=email, password=password, type="admin", hidden=True
            )

            # Create an empty index page
            page = Pages(title=ctf_name, route="index", content="", draft=False)

            # Upload banner
            default_ctf_banner_location = url_for("views.themes", path="img/logo.png")
            ctf_banner = request.files.get("ctf_banner")
            if ctf_banner:
                f = upload_file(file=ctf_banner, page_id=page.id)
                default_ctf_banner_location = url_for("views.files", path=f.location)
                set_config("ctf_banner", f.location)

            # Splice in our banner
            index = """


<style>
  /* Overall container with a retro parchment background */
.retro-container {
    padding: 20px;
  	width: 100vw;
  	margin: auto;
    font-family: "Courier New", Courier, monospace;
}

/* Section headings with a purple gradient effect (lighter purple from top to bottom) */
.section-heading {
    font-family: "Press Start 2P", cursive;
    text-align: left;
    margin-bottom: 15px;
    font-size: 2.0rem;
    background: linear-gradient(45deg, #5a4ee7, #6c47d3, #8b74e1);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: 1px 1px 0px rgba(0, 0, 0, 0.3);
}

p {
    font-size: 1.3rem;
    width: 100%;
    box-sizing: border-box; /* Ensure padding and borders are included in the width */
  	text-align: left;
}
  
.inline-container {
  display: flex;
  justify-items: center;
  align-items: center; /* Vertically center-align the items */
  font-size: 10px;
}
  
.rule-point {
  display: flex;
  justify-items: center;
  align-items: center; /* Vertically center-align the items */
  font-size: 10px;
  margin-left: 2rem;
}

.inline-arrow {
  width: 27px; /* Adjust the width as needed */
  height: auto;
  margin-right: 20px; /* Space between the arrow and the title */
  margin-bottom: 20px;
}
 
 .inline-triangle {
  width: 17px; /* Adjust the width as needed */
  height: auto;
  margin-right: 20px; /* Space between the arrow and the title */
  margin-bottom: 20px;
}
  
/* Section content styling */
.section-content {
    width: 100%;
    text-align: center;
    padding: 10px 20px;
    margin-bottom: 20px;
    position: relative;
}

h4, h3 {
    width: 100%;
    position: relative;
    display: block; /* Change to block to allow full-width expansion */
    text-align: left;
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
    text-align: left;
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
  input[type="text"],
  input[type="submit"] {
      align-items: center; /* Remove default margin */
  }
</style>

<style>
/* SPONSOR */
/* Container for the gold sponsor */
.gold-sponsor-container {
    border: 3px solid gold;
    padding: 20px;
    border-radius: 10px;
    position: relative;
    overflow: hidden;
    animation: glowBorder 2s infinite;
}

/* Keyframes for the glowing border animation */
@keyframes glowBorder {
    0%, 100% {
        border-color: gold;
        box-shadow: 0 0 10px gold;
    }
    50% {
        border-color: #FFD700;
        box-shadow: 0 0 20px #FFD700;
    }
}

/* Ensure the image and text are centered */
.gold-sponsor-container img {
    display: block;
    margin: 0 auto;
    max-width: 100%;
    height: auto;
}

.gold-sponsor-container h5,
.gold-sponsor-container p {
    text-align: center;
    color: gold;
}

.silver-sponsors-container {
    display: flex;
    justify-content: space-around;
    align-items: center;
    gap: 20px; /* Optional: Adds space between the items */
}

.golden-gradient-text {
    font-size: 2rem;
    background: linear-gradient(45deg, #FFD700, #FFA500, #FF8C00);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
}
.silver-sponsors-container {
    display: flex;
    justify-content: space-around;
    align-items: flex-start; /* Align items at the top */
    gap: 20px; /* Optional: Adds space between the items */
}

.sponsor-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    flex: 1;
    text-align: center;
    max-width: 50%;
}

.silver-gradient-text {
    font-size: 2rem;
    background: linear-gradient(45deg, #C0C0C0, #A9A9A9, #808080);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
}

.bronze-gradient-text {
    font-size: 2rem;
    background: linear-gradient(45deg, #CD7F32, #C47E46, #B5651D);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
}


</style>

<script>-
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
          src="/themes/pwnme2025/static/img/pwnme2025.png"
          alt="PWNME CTF Logo"
        />
      </div>
    </div>
    <div class="row">
      <div class="section-content glitch">
        <p style="text-align: center;">
          Participez à notre challenge de cybersécurité et testez vos compétences
          dans un environnement rétro et ludique.
        </p>
      </div>
    </div>
    <div style="height: 20vh;"></div>
    <div class="row">
      <div class="section-content glitch">
        <div class="inline-container">
          <img class="inline-arrow" src="/themes/pwnme2025/static/img/arrowright.svg" alt="arrow" />
          <h4 data-text="Quals schedule" class="section-heading quals-heading">Quals schedule</h4>
        </div>
        <div>
        	<p><strong>Qualification start:</strong> Fri 28th of February 2025</p>
        	<p><strong>Qualification end:</strong> Sun 2nd of Mars 2025</p>
        </div>
      </div>
    </div>
    <div style="height: 6rem;"></div>
    <div class="row">
      <div class="section-content glitch">
        <div class="inline-container">
          <img class="inline-arrow" src="/themes/pwnme2025/static/img/arrowright.svg" alt="arrow" />
          <h4  data-text="Finals schedule" class="section-heading quals-heading">Finals schedule</h4>
        </div>
      	<p><strong>Final:</strong> Sat 12th of April 2025</p>
      </div>
    </div>
    <div style="height: 6rem;"></div>
    <div class="row">
      <div class="section-content glitch">
      	<div class="inline-container">
          <img class="inline-arrow" src="/themes/pwnme2025/static/img/arrowright.svg" alt="arrow" />
        	<h4 data-text="Final location" class="section-heading location-heading">Final location</h4>
        </div>
        <p>
          12 bis Quai François Truffaut, 78180 Montigny-le-Bretonneux, France
        </p>
      </div>
    </div>
    <div style="height: 6rem;"></div>
    <div class="row">
      <div class="section-content glitch">
      	<div class="inline-container">
        	<img class="inline-arrow" src="/themes/pwnme2025/static/img/arrowright.svg" alt="arrow" />
        	<h4 data-text="Contact" class="section-heading contact-heading">Contact</h4>
        </div>
        <p>
          Email : <a href="mailto:contact@ctfxyz.com">contact@ctfxyz.com</a>
        </p>
      </div>
    </div>
    <div style="height: 6rem;"></div>
    <div class="row">
    <div class="section-content glitch">
        <div class="inline-container">
            <img class="inline-arrow" src="/themes/pwnme2025/static/img/arrowright.svg" alt="arrow" />
            <h4 data-text="Rules" class="section-heading contact-heading">Rules</h4>
        </div>
        <div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    Pets are welcome, but they can't solve challenges for you.
                </p>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    Wifi password is not "password123." Please stop asking.
                </p>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    No cheating allowed
                </p>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    Make sure to follow the rules
                </p>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    Every participant must be fair
                </p>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    {f you found the flag, you can submit here
                </p>
              <div class="rule-point" style="margin-bottom: 16px;">
                <input type="text" placeholder="Enter flag" />
                <input type="submit" value="Submit" />
              </div>
              <div style="width: 20rem;" ></div>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    Flags needs to be found
                </p>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    Losing is not allowed
                </p>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    Always respect other players
                </p>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    Good luck to all participants
                </p>
            </div>
            <div class="rule-point">
                <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
                <p class="text-left">
                    }f you have any problems, please contact rayanlecat
                </p>
            </div>
        </div>
    </div>
    </div>
    <div style="height: 6rem;"></div>
    <div class="row">
      <div class="section-content glitch">
      	<div class="inline-container">
            <img class="inline-arrow" src="/themes/pwnme2025/static/img/arrowright.svg" alt="arrow" />
            <h4 data-text="Prizes" class="section-heading prizes-heading">Prizes</h4>
        </div>
        <div>
          <div class="rule-point">
              <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
              <h5 class="section-heading" style="font-size: 1.4rem;">Academic Bracket</h5>
          </div>
          <ul class="text-left" style="margin-left: 2rem;">
            <li><strong>Top 3 Academic:</strong> Accommodation paid for the CTF finals</li>
            <li><strong>Top 8 Academic:</strong> Invited to PwnMe CTF finals</li>
          </ul>
        </div>
        <div style="height: 3rem;"></div>
        <div>
          <div class="rule-point">
              <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
              <h5 class="section-heading"  style="font-size: 1.4rem;">Professional Bracket</h5>
          </div>
          <ul class="text-left" style="margin-left: 2rem;">
            <li><strong>Top 3 Professional:</strong> Accommodation paid for the CTF finals</li>
            <li><strong>Top 8 Professional:</strong> Invited to PwnMe CTF finals</li>
          </ul>
        </div>
        <div style="height: 3rem;"></div>
        <div>
          <div class="rule-point">
              <img class="inline-triangle" src="/themes/pwnme2025/static/img/triangleright.svg" alt="triangle" />
              <h5 class="section-heading"  style="font-size: 1.4rem;">Additional Prizes</h5>
          </div>
          <ul class="text-left" style="margin-left: 2rem;">
            <li>Hack The Box Silver Annual x8</li>
            <li>Hack The Box VIP+ x8</li>
            <li>Hack The Box Store £100 x8</li>
            <li>Course and Cert Exam Bundle (OSCP or OSEP) x1</li>
            <li>HydraBus v1 Rev1.5 x4</li>
            <li>50€ on Lab401 x7</li>
            <li>50$ Hack5 x4</li>
          </ul>
        </div>
      </div>
    </div>
    <div style="height: 6rem;"></div>
    <div class="row">
      <div class="section-content glitch">
        <div class="inline-container">
            <img class="inline-arrow" src="/themes/pwnme2025/static/img/arrowright.svg" alt="arrow" />
            <h4 data-text="Sponsors" class="section-heading sponsors-heading">Sponsors</h4>
        </div>
        <div>
          	<img
                class="w-100 mx-auto d-block gold-sponsor-container"
          		style="max-width: 500px; padding: 50px;"
            	src="/themes/pwnme2025/static/img/GreenITSolutions.png" 
                alt="greenITSolution" 
            />
          	<div style="height: 3rem;"></div>
            <h5 class="section-heading text-center" style="font-size: 2rem;background: linear-gradient(45deg, #FFD700, #FFA500, #FF8C00);">Gold </h5>
          	<p class="text-center" style="font-size: 1.3rem;">Green IT Solutions, founded in 2011, specializes in providing sustainable and efficient IT services for SMEs. Our mission is to deliver robust, scalable IT solutions that prioritize environmental sustainability and operational efficiency. We focus on Haute Couture Numérique®, open-source solutions, and collaborative approaches to minimize the environmental impact of digital operations. Key achievements include deploying innovative cloud containers and achieving autonomous system status. We are committed to continuous innovation and reducing the carbon footprint of IT infrastructure, supporting our clients' growth while promoting a greener digital future.</p>
        </div>
        <div style="height: 10rem;"></div>
        <div class="silver-sponsors-container">
            <div class="sponsor-item">
                <img
                    class="w-100 mx-auto d-block"
                    style="max-width: 250px; padding: 25px;"
                    src="/themes/pwnme2025/static/img/fuzzinglabs.png"
                    alt="Fuzzinglabs"
                />
                <h5 class="section-heading text-center silver-gradient-text">Silver</h5>
                <p class="text-center" style="font-size: 1rem;">
Founded in 2021 and headquartered in Paris, FuzzingLabs is a cybersecurity startup specializing in vulnerability research, fuzzing, and blockchain security. We combine cutting-edge research with hands-on expertise to secure some of the most critical components in the blockchain ecosystem.</p>
            </div>
            <div class="sponsor-item">
                <img
                    class="w-100 mx-auto d-block"
                    style="max-width: 250px; padding: 25px;"
                    src="/themes/pwnme2025/static/img/epios.svg"
                    alt="Epios"
                />
              	<div style="height: 2.2rem;"></div>
                <h5 class="section-heading text-center silver-gradient-text">Silver</h5>
                <p class="text-center" style="font-size: 1rem;">
Founded by a cybersecurity and OSINT specialist with more than 10 years of experience, Epieos provides training, investigation and software services to organisations and individuals. We facilitate their efforts to collect and analyse open source information.</p>
            </div>
        </div>
        <div style="height: 10rem;"></div>
        <div class="silver-sponsors-container">
            <div class="sponsor-item">
                <img
                    class="w-100 mx-auto d-block"
                    style="max-width: 250px; padding: 25px;"
                    src="/themes/pwnme2025/static/img/quarkslab.png"
                    alt="Quarkslab"
                />
                <h5 class="section-heading text-center bronze-gradient-text">Bronze</h5>
                <p class="text-center" style="font-size: 1rem;">
Quarkslab is a company made up of teams of cybersecurity engineers and developers. Founded 10 years ago, our aim is to force attackers, not defenders, to constantly adapt.
Through QLab's R&D work and our QFlow and QShield software, Quarkslab develops and shares its security knowledge with the aim of making it accessible to all.</p>
            </div>
            <div class="sponsor-item">
                <img
                    class="w-100 mx-auto d-block"
                    style="max-width: 250px; padding: 25px;"
                    src="/themes/pwnme2025/static/img/Epsilonsec.svg"
                    alt="Epsilonsec"
                />
              	<div style="height: 2.2rem;"></div>
                <h5 class="section-heading text-center bronze-gradient-text">Bronze</h5>
                <p class="text-center" style="font-size: 1rem;">
Epsilon is a young security research company lead by French researchers.
We started our activity on the 9th of September 2024.
We do research on mobile platforms (iOS and Android). 
We also deliver private trainings and work on bespoke R&D projects.
We're hiring talented researchers who want to evolve in a friendly and benevolent environment.</p>
            </div>
        </div>
      </div>
    </div>
    <div style="height: 6rem;"></div>
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



"""
            page.content = index

            # Visibility
            set_config(ConfigTypes.CHALLENGE_VISIBILITY, challenge_visibility)
            set_config(ConfigTypes.REGISTRATION_VISIBILITY, registration_visibility)
            set_config(ConfigTypes.SCORE_VISIBILITY, score_visibility)
            set_config(ConfigTypes.ACCOUNT_VISIBILITY, account_visibility)

            # Verify emails
            set_config("verify_emails", verify_emails)

            # Team Size
            set_config("team_size", team_size)

            set_config("mail_server", None)
            set_config("mail_port", None)
            set_config("mail_tls", None)
            set_config("mail_ssl", None)
            set_config("mail_username", None)
            set_config("mail_password", None)
            set_config("mail_useauth", None)

            # Set up default emails
            set_config("verification_email_subject", DEFAULT_VERIFICATION_EMAIL_SUBJECT)
            set_config("verification_email_body", DEFAULT_VERIFICATION_EMAIL_BODY)

            set_config(
                "successful_registration_email_subject",
                DEFAULT_SUCCESSFUL_REGISTRATION_EMAIL_SUBJECT,
            )
            set_config(
                "successful_registration_email_body",
                DEFAULT_SUCCESSFUL_REGISTRATION_EMAIL_BODY,
            )

            set_config(
                "user_creation_email_subject", DEFAULT_USER_CREATION_EMAIL_SUBJECT
            )
            set_config("user_creation_email_body", DEFAULT_USER_CREATION_EMAIL_BODY)

            set_config("password_reset_subject", DEFAULT_PASSWORD_RESET_SUBJECT)
            set_config("password_reset_body", DEFAULT_PASSWORD_RESET_BODY)

            set_config(
                "password_change_alert_subject",
                "Password Change Confirmation for {ctf_name}",
            )
            set_config(
                "password_change_alert_body",
                (
                    "Your password for {ctf_name} has been changed.\n\n"
                    "If you didn't request a password change you can reset your password here: {url}"
                ),
            )

            set_config("setup", True)

            try:
                db.session.add(admin)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

            try:
                db.session.add(page)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

            login_user(admin)

            db.session.close()
            with app.app_context():
                cache.clear()

            return redirect(url_for("views.static_html"))
        try:
            return render_template("setup.html", state=serialize(generate_nonce()))
        except TemplateNotFound:
            # Set theme to default and try again
            set_config("ctf_theme", DEFAULT_THEME)
            return render_template("setup.html", state=serialize(generate_nonce()))
    return redirect(url_for("views.static_html"))


@views.route("/setup/integrations", methods=["GET", "POST"])
def integrations():
    if is_admin() or is_setup() is False:
        name = request.values.get("name")
        state = request.values.get("state")

        try:
            state = unserialize(state, max_age=3600)
        except (BadSignature, BadTimeSignature):
            state = False
        except Exception:
            state = False

        if state:
            if name == "mlc":
                mlc_client_id = request.values.get("mlc_client_id")
                mlc_client_secret = request.values.get("mlc_client_secret")
                set_config("oauth_client_id", mlc_client_id)
                set_config("oauth_client_secret", mlc_client_secret)
                return render_template("admin/integrations.html")
            else:
                abort(404)
        else:
            abort(403)
    else:
        abort(403)


@views.route("/notifications", methods=["GET"])
def notifications():
    notifications = Notifications.query.order_by(Notifications.id.desc()).all()
    return render_template("notifications.html", notifications=notifications)


@views.route("/settings", methods=["GET"])
@authed_only
def settings():
    infos = get_infos()
    errors = get_errors()

    user = get_current_user()

    if is_teams_mode() and get_current_team() is None:
        team_url = url_for("teams.private")
        infos.append(
            markup(
                f'In order to participate you must either <a href="{team_url}">join or create a team</a>.'
            )
        )

    tokens = UserTokens.query.filter_by(user_id=user.id).all()

    prevent_name_change = get_config("prevent_name_change")

    if get_config("verify_emails") and not user.verified:
        confirm_url = markup(url_for("auth.confirm"))
        infos.append(
            markup(
                "Your email address isn't confirmed!<br>"
                "Please check your email to confirm your email address.<br><br>"
                f'To have the confirmation email resent please <a href="{confirm_url}">click here</a>.'
            )
        )

    return render_template(
        "settings.html",
        name=user.name,
        email=user.email,
        language=user.language,
        website=user.website,
        affiliation=user.affiliation,
        country=user.country,
        tokens=tokens,
        prevent_name_change=prevent_name_change,
        infos=infos,
        errors=errors,
    )


@views.route("/", defaults={"route": "index"})
@views.route("/<path:route>")
def static_html(route):
    """
    Route in charge of routing users to Pages.
    :param route:
    :return:
    """
    page = get_page(route)
    if page is None:
        abort(404)
    else:
        if page.auth_required and authed() is False:
            return redirect(url_for("auth.login", next=request.full_path))

        return render_template("page.html", content=page.html, title=page.title)


@views.route("/tos")
def tos():
    tos_url = get_config("tos_url")
    tos_text = get_config("tos_text")
    if tos_url:
        return redirect(tos_url)
    elif tos_text:
        return render_template("page.html", content=build_markdown(tos_text))
    else:
        abort(404)


@views.route("/privacy")
def privacy():
    privacy_url = get_config("privacy_url")
    privacy_text = get_config("privacy_text")
    if privacy_url:
        return redirect(privacy_url)
    elif privacy_text:
        return render_template("page.html", content=build_markdown(privacy_text))
    else:
        abort(404)


@views.route("/files", defaults={"path": ""})
@views.route("/files/<path:path>")
def files(path):
    """
    Route in charge of dealing with making sure that CTF challenges are only accessible during the competition.
    :param path:
    :return:
    """
    f = Files.query.filter_by(location=path).first_or_404()
    if f.type == "challenge":
        if challenges_visible():
            if current_user.is_admin() is False:
                if not ctftime():
                    if ctf_ended() and view_after_ctf():
                        pass
                    else:
                        abort(403)
        else:
            # User cannot view challenges based on challenge visibility
            # e.g. ctf requires registration but user isn't authed or
            # ctf requires admin account but user isn't admin
            if not ctftime():
                # It's not CTF time. The only edge case is if the CTF is ended
                # but we have view_after_ctf enabled
                if ctf_ended() and view_after_ctf():
                    pass
                else:
                    # In all other situations we should block challenge files
                    abort(403)

            # Allow downloads if a valid token is provided
            token = request.args.get("token", "")
            try:
                data = unserialize(token, max_age=3600)
                user_id = data.get("user_id")
                team_id = data.get("team_id")
                file_id = data.get("file_id")
                user = Users.query.filter_by(id=user_id).first()
                team = Teams.query.filter_by(id=team_id).first()

                # Check user is admin if challenge_visibility is admins only
                if (
                    get_config(ConfigTypes.CHALLENGE_VISIBILITY) == "admins"
                    and user.type != "admin"
                ):
                    abort(403)

                # Check that the user exists and isn't banned
                if user:
                    if user.banned:
                        abort(403)
                else:
                    abort(403)

                # Check that the team isn't banned
                if team:
                    if team.banned:
                        abort(403)
                else:
                    pass

                # Check that the token properly refers to the file
                if file_id != f.id:
                    abort(403)

            # The token isn't expired or broken
            except (BadTimeSignature, SignatureExpired, BadSignature):
                abort(403)

    uploader = get_uploader()
    try:
        return uploader.download(f.location)
    except IOError:
        abort(404)


@views.route("/themes/<theme>/static/<path:path>")
def themes(theme, path):
    """
    General static file handler
    :param theme:
    :param path:
    :return:
    """
    for cand_path in (
        safe_join(app.root_path, "themes", cand_theme, "static", path)
        # The `theme` value passed in may not be the configured one, e.g. for
        # admin pages, so we check that first
        for cand_theme in (theme, *config.ctf_theme_candidates())
    ):
        # Handle werkzeug behavior of returning None on malicious paths
        if cand_path is None:
            abort(404)
        if os.path.isfile(cand_path):
            return send_file(cand_path, max_age=3600)
    abort(404)


@views.route("/themes/<theme>/static/<path:path>")
def themes_beta(theme, path):
    """
    This is a copy of the above themes route used to avoid
    the current appending of .dev and .min for theme assets.

    In CTFd 4.0 this url_for behavior and this themes_beta
    route will be removed.
    """
    for cand_path in (
        safe_join(app.root_path, "themes", cand_theme, "static", path)
        # The `theme` value passed in may not be the configured one, e.g. for
        # admin pages, so we check that first
        for cand_theme in (theme, *config.ctf_theme_candidates())
    ):
        # Handle werkzeug behavior of returning None on malicious paths
        if cand_path is None:
            abort(404)
        if os.path.isfile(cand_path):
            return send_file(cand_path, max_age=3600)
    abort(404)


@views.route("/healthcheck")
def healthcheck():
    if check_database() is False:
        return "ERR", 500
    if check_config() is False:
        return "ERR", 500
    return "OK", 200


@views.route("/debug")
def debug():
    if app.config.get("SAFE_MODE") is True:
        ip = get_ip()
        headers = dict(request.headers)
        # Remove Cookie item
        headers.pop("Cookie", None)
        resp = ""
        resp += f"IP: {ip}\n"
        for k, v in headers.items():
            resp += f"{k}: {v}\n"
        r = make_response(resp)
        r.mimetype = "text/plain"
        return r
    abort(404)


@views.route("/robots.txt")
def robots():
    text = get_config("robots_txt", "User-agent: *\nDisallow: /admin\n")
    r = make_response(text, 200)
    r.mimetype = "text/plain"
    return r

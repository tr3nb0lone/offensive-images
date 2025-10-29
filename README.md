## offensive-images
A personal feat into containerizing custom hacking environments. 

### What's included?
- An image for Bugbounty, with all the *necessary* tools installed.
- WIP: an image for tools *everything* related to hacking Active Directory.
- WIP: a custom light-weight Kali image.


### Credits:
- Exegol (took inspiration from this amazing project)

#### Typical usage:
```
# build the image:
docker build -t bountymage .

# run the image:
docker run --rm -it -e "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/tools/bin:/root/.pdtm/go/bin" bountymage:latest
```

#### Known caveats:
- The images are headless, i.e support for GUI is a WIP.
- The project is highly opinionated towards the tools I frequent on an engagement / CTFs.



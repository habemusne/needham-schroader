# Project Overview

Project Type: Course Project

Course Name: Introduction to Computer and Network Security

School: Penn State University

Level: Undergraduate

Project Requirement: [https://s3.amazonaws.com/habemusne-public/cmpsc443-project2/specification.pdf](https://s3.amazonaws.com/habemusne-public/cmpsc443-project2/specification.pdf)


# My Grade

300/300

[Canvas Screenshot](https://s3.amazonaws.com/habemusne-public/cmpsc443-project2/grade.png)

# Usage

1. Start docker daemon, then build and run: `docker-compose build && docker-compose up`
2. Open two terminals. In both of them, open a session to the docker instance: `docker-compose exec code /bin/bash`
3. At one of the terminals, compile my code: `make`
4. At one terminal, run `./cmpsc443_ns_server`. At the other, run `./cmpsc443_ns_client`
5. Kindly reminded to stop the docker instance after done playing with the program: logout both sessions, and then `docker-compose stop`

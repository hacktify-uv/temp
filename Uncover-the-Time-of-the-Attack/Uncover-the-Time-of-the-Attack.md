**Scenario Overview**

A suspicious website has been linked to a potential attack. Your mission is to identify vulnerabilities in the website and extract critical information to determine the **time of the attack**. This walkthrough documents the systematic approach to uncovering the hidden data.

#### **Step-by-Step Guide**

------------------------------------------------------------------------

### Step 1: Initial Analysis

1.  <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image1.png" style="width:6.26806in;height:3.10625in" />

2.  **Access the Login Page**

3.  - URL: http://example.com/login.php

    - The website requires login credentials to access user-specific information.

> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image2.png" style="width:6.26806in;height:3.20139in" />

4.  **Form Testing**

    - Enter arbitrary usernames and passwords to understand the behavior of the login system.

    - Observe error messages such as "Invalid username or password" to confirm validation processes.

> <img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image3.png" style="width:6.26806in;height:5.9in" />

### Step 2: Exploit Login Page Vulnerability

1.  **Test SQL Injection Payloads**

    - Use crafted payloads in the **username** field to bypass authentication. Examples include:

      - ' OR 1=1 --

      - ' OR ''='

      - admin' â€“

      - admin' OR '1' = '1

    - Leave the password field blank or input arbitrary data.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image4.png" style="width:6.26806in;height:5.23333in" />

- A successful payload results in access to the user dashboard.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image5.png" style="width:6.26806in;height:3.66111in" />

### Step 3: Access User Profiles

1.  **Identify Profile URL Pattern**

    - After login, observe the URL structure:

> <http://example.com/profile.php?id=1>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image6.png" style="width:6.26806in;height:3.71875in" />

2.  **Profile Enumeration**

    - Increment the id parameter in the URL to explore other user profiles:

      - http://example.com/profile.php?id=2

      - http://example.com/profile.php?id=3

    - Examine the content of each profile for clues or sensitive information.

### Step 4: Extract Clues

1.  **User id=4: Source Code Hint**

    - The profile displays the following message:

> Welcome, User 5! (Hint: Try harder. You're very close.)

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image7.png" style="width:6.26806in;height:4.12847in" />

- View the page source (Ctrl+U or Cmd+U) to locate a hidden comment:

- You will able to see a hidden key in the comment \<!-- Key: c2VjcmV0a2V5MTIz --\>

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image8.png" style="width:6.26806in;height:4.68403in" />

- Decode the Key using **Base64** c2VjcmV0a2V5MTIz

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image9.png" style="width:6.26806in;height:3.70069in" />

- After Decoding it you will get a key **secretkey123**

2.  **User id=7: Embedded Image**

    - The profile displays the message:

> Welcome, User 7! (Image of London is below. But is it just an image?)

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image10.png" style="width:6.26806in;height:3.60486in" />

- Download the displayed image, london.jpeg

### Step 5: Decode Hidden Information

1.  **Extract Hidden Data**

    - Use the stego key (secretkey123) retrieved from User id=4 to decode the image:

> steghide extract -sf london.jpeg -p "secretkey123"

2.  **Analyze the Extracted Data**

    - A text file is extracted containing the flag:

> flag{2245GMT}

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Uncover-the-Time-of-the-Attack/media/image11.png" style="width:6.26806in;height:4.01389in" />

------------------------------------------------------------------------

### Conclusion

Through systematic exploitation of vulnerabilities, the **time of the attack** was revealed as **22:45 GMT**.

------------------------------------------------------------------------

### Key Findings

1.  **SQL Injection**

    - The login form was vulnerable to SQL Injection, allowing attackers to bypass authentication.

    - Effective payloads included:

      - ' OR 1=1 --

      - admin' â€“

      - admin' â€“

      - admin' OR '1' = '1

2.  **Insecure Direct Object References (IDOR)**

    - Manipulating the id parameter allowed access to unauthorized profiles.

3.  **Steganography**

    - A hidden message was embedded in london.jpeg and decoded using a stego key.

### Conclusion

Through systematic exploitation of vulnerabilities, the **time of the attack** was revealed as **22:45 GMT**.


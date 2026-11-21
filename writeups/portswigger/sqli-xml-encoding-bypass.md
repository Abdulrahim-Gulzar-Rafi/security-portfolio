# SQL Injection – Filter Bypass via XML Encoding

## 1. Summary

This lab demonstrated how SQL injection can be used to bypass a WAF by encoding SQL keywords as XML entities. The vulnerability existed because the application concatenated user-controlled `storeId` input directly into an SQL query, allowing me to retrieve usernames and passwords from the database. The primary fix is to use parameterised queries with proper type validation.

## 2. Reconnaissance

I started by exploring the application's functionality and monitoring its requests through Burp Suite.

While reviewing the HTTP history, I noticed a stock-check request that sent data in XML format. The request contained a `<storeId>` parameter, which looked like a potential injection point.

I sent the request to Repeater and started testing how the application handled modified input.

## 3. Exploitation

**Step 1 – Identifying the injection point**

I tested the `<storeId>` parameter with a basic SQL injection payload.

The parameter was in a numeric context, meaning I didn't need to use a single quote to break out of a string. I could directly append SQL syntax to the numeric value.

**Step 2 – Testing the WAF**

I tried a UNION-based SQL injection payload:

```sql
1 UNION SELECT username FROM users
```

However, the WAF blocked the request because it recognised the SQL keywords.

**Step 3 – Bypassing the WAF using Hackvertor**

I used the Hackvertor extension in Burp Suite to encode the SQL payload as XML entities.

The payload I used was:

```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>
```

The WAF inspected the encoded request and allowed it through. After that, the application's XML parser decoded the entities, restoring the original SQL payload.

**Step 4 – Retrieving credentials**

The original query returned only one column, so I used SQL concatenation (`||`) to combine the username and password into a single result column, separated by `~`.

This allowed me to retrieve both values using one UNION SELECT statement.

I was able to retrieve the administrator's username and password from the users table.

## 4. Root Cause and Why the Defence Failed

**Root cause – Unsafe SQL construction**

The actual vulnerability was caused by concatenating the user-controlled `storeId` value directly into the SQL query.

The application trusted the input and inserted it into the SQL statement without parameterisation. This allowed the input to change the structure and behaviour of the query.

**Why the defence failed – WAF and XML parsing**

The WAF inspected the raw XML request before the application processed it. Since the SQL keywords were encoded as XML entities, the WAF did not recognise them.

The XML parser subsequently decoded those entities. As a result, the application received the original SQL syntax and passed it into the dynamically constructed query.

The WAF bypass made the attack possible despite the filtering, but the underlying SQL injection existed because of unsafe query construction.

## 5. Fix – Java Implementation

**Vulnerable approach – String concatenation**

```java
// getTextContent() returns the decoded XML text.
// The encoded SQL payload is now back to normal SQL syntax.
String storeId = doc.getElementsByTagName("storeId")
                    .item(0).getTextContent();

String sql = "SELECT units FROM stock WHERE product_id = "
             + productId + " AND store_id = " + storeId;

Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

The problem is that the decoded `storeId` value is directly concatenated into the SQL query. An attacker can therefore manipulate the query by supplying specially crafted input.

**Fixed approach – Type validation and PreparedStatement**

```java
String storeIdText = doc.getElementsByTagName("storeId")
                        .item(0).getTextContent();

// Validate that storeId is a valid integer
int storeId = Integer.parseInt(storeIdText);

PreparedStatement ps = conn.prepareStatement(
    "SELECT units FROM stock WHERE product_id = ? AND store_id = ?"
);

ps.setInt(1, productId);
ps.setInt(2, storeId);

ResultSet rs = ps.executeQuery();
```

Here, the input is converted to an integer and passed as a parameter rather than being concatenated into the SQL statement. This ensures that user input is treated as data, not executable SQL.

**Additional security improvements:**

- **Password storage:** The lab stores passwords in plaintext. Passwords should instead be stored using a secure password-hashing algorithm such as bcrypt or Argon2.
- **XML security:** Since the endpoint accepts user-supplied XML, external entities should be disabled in the XML parser to prevent XML External Entity (XXE) attacks.

WAFs and input filtering are useful as additional layers of defence, but they are not substitutes for secure coding practices. The actual SQL injection must be fixed at the application level using parameterised queries.

## 6. Lessons Learned

- **Never rely entirely on WAFs:** Security filters can sometimes be bypassed through encoding and parsing differences. The application itself must handle untrusted input safely.
- **Understand how data is processed:** Input can change representation as it passes through different application layers. What the WAF sees may not be what the application eventually processes.
- **Secure the entire data flow:** Fixing SQL injection is important, but other weaknesses such as plaintext password storage and insecure XML parsing should also be considered when reviewing an endpoint.

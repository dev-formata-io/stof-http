# Stof HTTP
Stof HTTP library. Adding this library to your Stof document allows you to make HTTP requests.

## Example
Here is an example of using this library in Stof.

``` rust
fn example(): str {
    let url = "https://restcountries.com/v3.1/name/germany";
                
    // Using a response object, we are telling the document to call header_import using the responses 'content-type' as a format,
    // parsing the response into this object. The object can be created like so, or be an already created obj in the document somewhere.
    let obj = new {};
    let resp = HTTP.get(url, obj);
    
    // resp is in the form (content type (str), headers (vec), body (blob))
    // return resp[2] as str; // This would convert the blob body to a string using utf-8, returning the entire response body
    
    let first = obj.field[0];
    return `${first.altSpellings[1]} has an area of ${first.area}`; // returns 'Federal Republic of Germany has an area of 357114'
}
```

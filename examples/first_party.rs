extern crate macaroon;
extern crate serde_json;
extern crate chrono;

use macaroon::macaroon::{Macaroon, Caveat};
use macaroon::verifier::Verifier;
use sodiumoxide::crypto::auth;

fn main() {
    // Construct a macaroon and serialize it
    let key = auth::gen_key();
    let identifier = "App1";
    let mut m = Macaroon::new(&key, identifier.into(), None).unwrap();
    let data = serde_json::to_string(&m).unwrap();
    println!("initial macaroon: {}", data);
    println!("key used was: {:?}", &key);

    // Add some caveats to the macaroon and then serialize the macaroon (and
    // deserialize, for example sake)
    // m.add_first_party_caveat(Caveat{
    //     identifier: "labels = not bacon".into(),
    //     ..Default::default()
    // }).unwrap();


    m.add_first_party_caveat(Caveat{
        identifier: "labels = bacon".into(),
        ..Default::default()
    }).unwrap();

    // m.add_first_party_caveat(Caveat{
    //     identifier: "x = y".into(),
    //     ..Default::default()
    // }).unwrap();

	// m.add_first_party_caveat(Caveat{
    //     identifier: "foo = baz".into(),
    //     ..Default::default()
    // }).unwrap();

    // m.add_first_party_caveat(Caveat{
    //     identifier: "app = me".into(),
    //     ..Default::default()
    // }).unwrap();


    let expire = chrono::Utc::now() + chrono::Duration::hours(5);
    m.add_first_party_caveat(Caveat{
        identifier: format!("time < {}", expire.to_rfc3339()).into(),
        ..Default::default()
    }).unwrap();

    let data = serde_json::to_string(&m).unwrap();

    println!("this time with caveeats (and serialised): {}", data);
    let deserialized: Macaroon = serde_json::from_str(&data).unwrap();
	println!("this time with caveeats (and deserialized): {:?}", deserialized);
    println!("so lets check if the deserialized sig matches macaroon sig: {:?}", deserialized.signature == m.signature);

    // Succeeding verification
    let mut v = Verifier::default();

	// aha, things to check when we call verify
    v.satisfy_exact("labels = bacon".into());

	// if caveat identifier doesnt exist on macaroon its ignored...
    v.satisfy_exact("nonexistant = nothing".into());
    // v.satisfy_exact("user = me".into());

	println!("About to mess with sig");
    // A general expiry example
    v.satisfy_general(Box::new(is_expired));
    v.verify(&m, &key, Vec::new()).unwrap();

    let correct_sig = m.signature.clone();
    m.signature = "ohnoesthisisbad".into();
    match v.verify(&m, &key, Vec::new()) {
        Ok(_) => (),
        Err(e) => println!("Someone messed with me {:?}", e)
    };

    m.signature = correct_sig;

    // Failing verification
    m.add_first_party_caveat(Caveat{
        identifier: "foo = baz".into(),
        ..Default::default()
    }).unwrap();


    match v.verify(&m, &key, Vec::new()) {
        Ok(_) => (),
        Err(e) => println!("I didn't validate.... as there's a caveat not checked... {:?}", e)
    };

	v.satisfy_exact("foo = baz".into());

    match v.verify(&m, &key, Vec::new()) {
        Ok(_) => println!("Validated now, as we check all caveats...."),
        Err(e) => println!("I didn't validate.... because something is wrong {:?}", e)
    };
}

fn is_expired(c: &Caveat) -> bool {
    let prefix = "time < ".as_bytes();
    if !c.identifier.0.starts_with(&prefix) {
        return false
    }
    let time_str = match std::str::from_utf8(c.identifier.0.split_at(prefix.len()).1) {
        Ok(s) => s,
        Err(_) => return false
    };
    let time = match time_str.parse::<chrono::DateTime<chrono::Utc>>() {
        Ok(t) => t,
        Err(_) => return false
    };
    let now = chrono::Utc::now();
    return time >= now
}

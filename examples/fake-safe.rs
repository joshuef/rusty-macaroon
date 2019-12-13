extern crate macaroon;
extern crate serde_json;
extern crate chrono;

use macaroon::macaroon::{Macaroon, Caveat};
use macaroon::verifier::Verifier;
use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::auth::hmacsha512256::Key;

fn authenticator() -> (Key, Macaroon ) {
	// Construct a macaroon and serialize it
	let secret_key = auth::gen_key();
	let identifier = "App1";
	let mut macaroon = Macaroon::new(&secret_key, identifier.into(), None).unwrap();
	let data = serde_json::to_string(&macaroon).unwrap();

	(secret_key, macaroon)
	// println!("initial macaroon: {}", data);
	// println!("secret_key used was: {:?}", &secret_key);
}

fn permission_request( macaroon: &mut Macaroon ) {
	macaroon.add_first_party_caveat(Caveat{
		identifier: "labels = bacon".into(),
		..Default::default()
	}).unwrap();

}

fn main() {

	let ( secret_key, mut macaroon ) = authenticator();

	println!("KEY {:?}", secret_key);
	println!("macaroon {:?}", macaroon);


	permission_request( &mut macaroon );

    // Add some caveats to the macaroon and then serialize the macaroon (and
    // deserialize, for example sake)
    macaroon.add_first_party_caveat(Caveat{
        identifier: "labels = bacon".into(),
        ..Default::default()
    }).unwrap();

    // macaroon.add_first_party_caveat(Caveat{
    //     identifier: "x = y".into(),
    //     ..Default::default()
    // }).unwrap();

	// macaroon.add_first_party_caveat(Caveat{
    //     identifier: "foo = baz".into(),
    //     ..Default::default()
    // }).unwrap();

    // macaroon.add_first_party_caveat(Caveat{
    //     identifier: "app = me".into(),
    //     ..Default::default()
    // }).unwrap();


    let expire = chrono::Utc::now() + chrono::Duration::hours(5);
    macaroon.add_first_party_caveat(Caveat{
        identifier: format!("time < {}", expire.to_rfc3339()).into(),
        ..Default::default()
    }).unwrap();

    let data = serde_json::to_string(&macaroon).unwrap();

    println!("this time with caveeats (and serialised): {}", data);
    let deserialized: Macaroon = serde_json::from_str(&data).unwrap();
	println!("this time with caveeats (and deserialized): {:?}", deserialized);
    println!("so lets check if the deserialized sig matches macaroon sig: {:?}", deserialized.signature == macaroon.signature);

    // Succeeding verification
    let mut v = Verifier::default();

	// aha, things to check when we call verify
    v.satisfy_exact("labels = bacon".into());
    // v.satisfy_exact("user = me".into());

	println!("About to mess with sig");
    // A general expiry example
    v.satisfy_general(Box::new(is_expired));
    v.verify(&macaroon, &secret_key, Vec::new()).unwrap();

    let correct_sig = macaroon.signature.clone();
    macaroon.signature = "ohnoesthisisbad".into();
    match v.verify(&macaroon, &secret_key, Vec::new()) {
        Ok(_) => (),
        Err(e) => println!("Someone messed with me {:?}", e)
    };

    macaroon.signature = correct_sig;

    // Failing verification
    macaroon.add_first_party_caveat(Caveat{
        identifier: "foo = baz".into(),
        ..Default::default()
    }).unwrap();


    match v.verify(&macaroon, &secret_key, Vec::new()) {
        Ok(_) => (),
        Err(e) => println!("I didn't validate.... as there's a caveat not checked... {:?}", e)
    };

	v.satisfy_exact("foo = baz".into());

    match v.verify(&macaroon, &secret_key, Vec::new()) {
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

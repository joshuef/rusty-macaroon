extern crate macaroon;
extern crate serde_json;
extern crate chrono;

use macaroon::macaroon::{Macaroon, Caveat};
use macaroon::verifier::Verifier;
use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::auth::hmacsha512256::Key;


fn permission_request() -> (Key, Macaroon) {

	// Construct a macaroon and serialize it
	let secret_key = auth::gen_key();
	let identifier = "App1";
	let mut macaroon = Macaroon::new(&secret_key, identifier.into(), None ).unwrap();
	let data = serde_json::to_string(&macaroon).unwrap();


	macaroon.add_first_party_caveat(Caveat{
		identifier: "labels = [bacon]".into(),
		..Default::default()
	}).unwrap();


	let expire = chrono::Utc::now() + chrono::Duration::hours(5);
	macaroon.add_first_party_caveat(Caveat{
	    identifier: format!("time < {}", expire.to_rfc3339()).into(),
	    ..Default::default()
	}).unwrap();

	let data = serde_json::to_string(&macaroon).unwrap();

	println!("\n\n Macaroon to give to apps (and serialised): {} \n\n", data);


	let deserialized: Macaroon = serde_json::from_str(&data).unwrap();
	// println!("this time with caveeats (and deserialized): {:?}", deserialized);

	println!("so lets check if the deserialized sig matches macaroon sig: {:?}", deserialized.signature == macaroon.signature);
	(secret_key, macaroon)

}


fn is_valid_at_client_handler( macaroon: &Macaroon, secret_key: Key ) -> bool {

    // Succeeding verification
    let mut v = Verifier::default();

	// aha, things to check when we call verify
    // v.satisfy_exact("user = me".into());

    // Could also check it's no expired here...
    v.satisfy_general(Box::new(is_expired));
    v.satisfy_general(Box::new(has_label_for_data));

	// we check that the macaroon is valid by comparing to auth stored secret key.
    v.verify(&macaroon, &secret_key, Vec::new()).unwrap();

	true


}

// we could pass a signed message if we want to establish ownership etc....
fn is_valid_at_data_handler( perms: Vec<String>, _sig: Option<String> ) -> bool {
	// TODO, check perms / labels.

	// println!("perms received for check, {:?}", perms );

	true

}


fn get_perms_for_app( macaroon: &Macaroon ) -> Vec<String> {
	let caveats = macaroon.get_first_party_caveats().clone();

	let mut perms = vec![];
	for cav in &caveats {
		// println!("\n\nCaveats found:: {:?}", cav.identifier.0 );
		// println!("\n\nCaveats found:: {:?}", std::str::from_utf8( &cav.identifier.0 ) );
		perms.push(std::str::from_utf8( &cav.identifier.0 ).unwrap().to_string());
	}

	perms
}

fn main() {

	// auth generates initial macaroon, adding caveats for app
	let ( secret_key, mut macaroon ) = permission_request();

	println!("KEY {:?}", secret_key);
	println!("macaroon {:?}", macaroon);

	// secret key must be stored in client handler for checks...
	// when a request comes in it is used to validate the macaroon

	//client handler checks, against req and for other perms it cares about
	// may also check other conditions we want to make available to folk
	// (ie expiry time added by user)
	// could perhaps have safecoin checks eg.
	is_valid_at_client_handler( &macaroon, secret_key );


	// we would then either forward macaroon + key to data handler.
	// or extract labels and pass them on...
	let perms = get_perms_for_app( &macaroon );
	println!("perms found {:?}", perms);

	// data handler does its own checks
	is_valid_at_data_handler(perms, None);

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

// get the labels from our data.
fn get_data_labels() -> Vec<String> {
	vec!["bacon".to_string(), "sandwhich".to_string(),]
}

fn has_label_for_data( c: &Caveat ) -> bool {
	let prefix = "labels =".as_bytes();
    if !c.identifier.0.starts_with(&prefix) {
        return false
    }

	let labels = get_data_labels();
	let caveat_labels = std::str::from_utf8( &c.identifier.0 ).unwrap();

	// println!("cav labels: {:?}", &caveat_labels);
	let mut has_a_label = false;

	for label in &labels {
		// naiive check. should be more exacting ofc.
		if caveat_labels.contains(label) {
			has_a_label = true
		}
	}

	has_a_label

}

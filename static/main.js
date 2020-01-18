for(var i =0;i<WORD.length;i++){
$.getJSON('https://googledictionaryapi.eu-gb.mybluemix.net/?define=' +WORD[0] +'&lang=en', function (data) {
    $('ul').append('<li><h1>{{word}}</h1></li>');
    console.log(data);
    verb = data[0].meaning.verb;
    console.log(verb);
    if (verb) {

        $('ul').append('<li>verb</li>')
        $('ul').append('<li>' + verb[0].definition + '</li>')
        $('ul').append('<li>' + verb[0].example + '</li>')
    }
    noun = data[0].meaning.noun;
    if (noun) {
        console.log(noun.length)
        for (var i = 0; i < noun.length; i++) {
            $('ul').append('<li>noun</li>')
            $('ul').append('<li>' + noun[i].definition + '</li>')
            $('ul').append('<li>' + noun[i].example + '</li>')
        }
    }
});
}
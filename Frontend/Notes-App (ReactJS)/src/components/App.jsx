import React, { useState } from "react";
import Header from "./Header";
import Footer from "./Footer";
import Note from "./Note";
import NewNote from "./NewNote";

function App() {
  const [notesArray, setNotes] = useState([]);

  function fillNotes(note) {
    return (
      <Note
        key={note.id}
        title={note.title}
        content={note.body}
      />
    );
  }

  return (
    <div className="Youri">
      <Header />
      <NewNote notesArray={notesArray} setNotes={setNotes} />
      {notesArray.map(fillNotes)}
      <Footer />
    </div>
  );
}

export default App;

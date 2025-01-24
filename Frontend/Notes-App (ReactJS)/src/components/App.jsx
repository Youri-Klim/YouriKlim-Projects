import React, { useState } from "react";
import Header from "./Header";
import Footer from "./Footer";
import Note from "./Note";
import NewNote from "./NewNote";

function App() {
  const [notesArray, setNotes] = useState([]);

  function handleDelete(noteId) {
    setNotes((prevNotes) => prevNotes.filter((note) => note.id !== noteId));
  }

  return (
    <div className="Youri">
      <Header />
      <NewNote notesArray={notesArray} setNotes={setNotes} />
      {notesArray.map((note) => (
        <Note
          key={note.id}
          id={note.id}
          title={note.title}
          content={note.body}
          onDelete={handleDelete}
        />
      ))}
      <Footer />
    </div>
  );
}

export default App;

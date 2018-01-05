/*
	Automated network tests project.
	Program AnetTest.
	Author: Titov A.V.
	File: anettestTextBuffer.h
	Description:
		class AnettestTextBuffer for performing various operations with text,
		other text functions

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
  USA
*/

#include "stdafx.h"
#include "anettestTextBuffer.h"

MString AnettestTextBuffer :: lineFeedSubstitution = "\n";
DefaultFormatNumber AnettestTextBuffer :: defaultFormatNumber = ND_DEC;
vector<ValueType const*> AnettestTextBuffer :: knownValueTypes;

bool AnettestTextBuffer :: isEnclosedInApostrophes(const MString& word) {

	if (word.size() < 2) return false;
	if ((word[0] == '\'' || (word.size() > 2 && word[0] == '.' && word[1] == '\'')) && word[word.size() - 1] == '\'') return true;
	return false;
}

bool AnettestTextBuffer :: isQuoted(const MString& word) {

	if (word.size() < 2) return false;
	if ((word[0] == '\'' || (word.size() > 2 && word[0] == '.' && word[1] == '\'')) && word[word.size() - 1] == '\'') return true;
   if ((word[0] == '\"' || (word.size() > 2 && word[0] == '.' && word[1] == '\"')) && word[word.size() - 1] == '\"') return true;
	return false;
}

const ValueType* AnettestTextBuffer :: getValueTypeByName(const MString& name) {

   for (int i = 0; i < knownValueTypes.size(); i++) {
      if (name == knownValueTypes[i] -> getName()) {
         return knownValueTypes[i];
      }
   }
	return 0;
}

void AnettestTextBuffer :: removeEnclosingCommas(MString* word) {

	if (word -> size() < 2) return;

	if (		
			((*word)[0] == '\'' && (*word)[(*word).size() - 1] == '\'')
			|| ((*word)[0] == '"' && (*word)[(*word).size() - 1] == '"')		
		) {

		(*word).erase(0, 1);
		(*word).erase((*word).size() - 1, 1);	
	}
}

RefHolder<FieldValue>& AnettestTextBuffer :: readValueUndefinedType(RefHolder<FieldValue>& refh, const char* word, bool implicitString) throw(Exception*) {

   FieldValue* value = 0;  

   string string(word);
   
   for (int i = 0; i < knownValueTypes.size(); i++) {
      if (knownValueTypes[i] -> isAcceptedValue(string)) {
         value = new FieldValue(knownValueTypes[i]);
         value -> readValue(word);
         refh.set(value);
         return refh;
      }
   }

   throw new Exception("word '%s' doesn't correspond to any type of value", word);
}          

DBuffer AnettestTextBuffer :: readNumber(const char* numberString, DefSize requiedSize) throw (Exception*) {

	DBuffer numberBuffer;
	char* ch;	
	u_int size = requiedSize.isUndefined() ? 1 : requiedSize.num();
	uint i;
	TypeCode type=VT_DEC;

	numberBuffer.setSize(0);

	//if (determinedValueType) *determinedValueType = &(BaseType :: UNDEFINED_TYPE);

	try 
   {
		// determines the typed of number (decimal or hexadecimal)

		if (AnettestTextBuffer :: defaultFormatNumber == ND_HEX) type = VT_HEX;
		if (AnettestTextBuffer :: defaultFormatNumber == ND_DEC) type = VT_DEC;

		if (numberString[0] == '0') {
			
			if (numberString[1] == 'x') type = VT_HEX;		
		}

		if (strchr(numberString,'.')) type = VT_DEC;

		//if (determinedValueType) *determinedValueType = &type;


		// at least the string must be a hexadecimal number
		if (!BaseType :: is_hex(numberString) && !BaseType :: is_dec(numberString)) {

			throw new Exception("given '%s', but expected some NUMBER", numberString);      
		}

		// obtaining the s symbole, after which the size of number must be specified
		if ((ch = strchr((char*)numberString,'s')) != 0) {	

			try {

				size = atoi(ch+1);
				if (size == 0) {

					// no size after symbole s

					throw new Exception("given '%s', but expected NUMBER", numberString);
				}
				if (!requiedSize.isPermitted(size)) {

					// the size after symbole s not equal the size given to function

					throw new Exception("given '%s', but expected value with size = %i bytes", numberString, requiedSize.num());
				}

				requiedSize = size;
			}

			ADD_TO_ERROR_DESCRIPTION("in case of number, after symbol 's' must be given the number's size > 0, example '34s3' - value 34 with size = 3 bytes");
		}
			

		// symbole u indicates that the sequence of equal bytes must be written

		if (strchr((char*)numberString,'s') && (ch=strchr((char*)numberString,'u')) != 0) {

			u_int o = 0;

			type = VT_HEX;
			//if (determinedValueType) *determinedValueType = &type;
						
			sscanf(numberString, "%x", &o);
						
			for (i = 0; i < size; i++) {
						
				numberBuffer.setByte(i, (u_char)o);
			}			
		}		
      else if (type == VT_DEC) {

         // works with decimal number

			if (requiedSize.isForVariable()) {
				size = sizeof(decimal_number_type);
			}
			
			if (size > sizeof(decimal_number_type)) {

				throw new Exception("given '%s', but the size of decimal number must be not greater %i bytes", numberString, sizeof(decimal_number_type));
			}
						
			if (!BaseType :: is_dec(numberString)) {

				throw new Exception("given '%s', but expected DECIMAL numer",numberString);
			}
						
			decimal_number_type num;
			if (BaseType :: read_dec_number(numberString,(decimal_number_type*)&num)) {

				throw new Exception("given '%s', but it's too big for decimal number, use hexadecimal format for big numbers",numberString);
			}
						
			if (size < sizeof(decimal_number_type) && num >= ((decimal_number_type)1 << (size * 8))) {

            if (requiedSize.isDefined())
               throw new Exception("given '%s', but expected value no more %i bytes",numberString, size);
            else if (size == 1)
               throw new Exception("given '%s', but the value is more than 255 (1 byte) : for such decimal numbers their size must be specified after symbol 's'",numberString);
			}
			
			rev_order((void*)&num, size);
			
			numberBuffer.fill((u_char*)&num, size);
		}
      else {
		// ******* works with hexadecimal number *********
		
         readHexNumber(numberString, requiedSize, numberBuffer);
      }
	}
									 
	ADD_TO_ERROR_DESCRIPTION2("reading %s number", type == VT_HEX ? "hexadecimal" : "decimal");	

	return numberBuffer;
}

void AnettestTextBuffer :: pass_space() {

	try {
	for (; ISSPACE(text[pos]); pos ++)

		if (text[pos] == '\n'
		 && pos > positionOfLastFoundLineFeed) { // as this method may run several times through some parts of text

			positionOfLastFoundLineFeed = pos;
			lineNumber ++;
		}
	} //try

	catch (OutOfBufferBorders* e) { delete e; }
}

MString& AnettestTextBuffer :: nextWord(MString& word, bool failOnEmptyWord) throw(Exception*) {

   int i;
	bool apos = false;		// true: apostrophes enclosed text is currently being read
	bool quotes = false;		// true: quoted text is currently being read
   bool com1 = false;	// comments after // 
   bool com2 = false;	// comments between /* */		
	MString nextWord;

	word = "";
	nextWord = ""; // ATTENTION: must be filled synchronously to 'word'

	try {

   do {
      
      pass_space();
      
		// reads symbols till a first space symbol
		// append read symbols to 'word' if it's not quote, comments, ...

      for (i = 0; ((quotes || com1 || com2 || apos || !ISSPACE(text[pos]))); pos++) {

			if (text[pos] == 13) continue;

         // counds LF
			if (text[pos] == 10 && pos > positionOfLastFoundLineFeed) {

				positionOfLastFoundLineFeed = pos;
				lineNumber ++;
         }			

         // registrates the start of commetns // till the end of line
			if (!quotes && !apos && !com2 && text[pos] == '/' && text[pos+1] == '/') {

				if (i) break;  // finish reading of word, return the word read before commetns
				com1 = true;
				lastComments.clear();
			}

			// registrates the start of commetns /* ... */
			if (!quotes && !apos && !com1 && text[pos] == '/' && text[pos+1] == '*') {

				if (i) break;	// finish reading of word, return the word read before commetns
				com2 = true;
				lastComments.clear();
			}

			// registrates the end of commetns /* ... */
         if (com2 && text[pos] == '*' && text[pos+1] == '/') {

				com2 = false;
            pos += 2;		
				break;
         }

			// registrates the end of commetns //
         if (com1 && text[pos] == '\n') {

            com1 = false;
				pos ++;
            break;
         }		

			if (com1 || com2) {

				if (text[pos] != '/')
					lastComments.append((const char*)&text[pos], 1);
			}
			         
         if (!com2 && !com1) {
			
				MString symbolReplacement;

				symbolReplacement.resize(1);
				symbolReplacement.at(0) = text[pos];				

				// replace LF by user defined string

				if ((apos || quotes) && text[pos] == '\n') {

					symbolReplacement = lineFeedSubstitution;	
				}

				// APPENDS THE SYMBOLE TO THE WORD
								
				nextWord.append(symbolReplacement);

				// finishes word on a special symbol

				if (!apos && !quotes  && !isAtomWord(nextWord))  {
					
					if (word.size() != 0) {
						
						if (isSpecialSymbol(text[pos]))												
							break;						

						if (isSpecialSymbol(word[0])) 
							if (isAtomWord(word)) 
								break;
					}					
				}

				if ((apos || quotes) && text[pos] == '\\') { 

					// PROCESSES \ CHARACTER
					
					if (pos >= text.getSize() - 1)
						throw new Exception("\\ at the end of file");

					pos ++;
					if (text[pos] == 13) pos ++;

					if (pos >= text.getSize() - 1)
						throw new Exception("\\ at the end of file");

					char newCh;               
					newCh = text[pos];
					if (newCh != 'x') {

						// escaped character						

						switch (text[pos]) {
										
							case 'r': newCh = '\r';	break;
							case 'n': newCh = '\n'; break;
							case 't': newCh = '\t'; break;
							case 'a': newCh = '\a'; break;
							case 'b': newCh = '\b'; break;														
						}
						if (newCh != text[pos] 
						   || newCh == '\\' || newCh == '\n' || newCh == '\'' || newCh == '"') {
							nextWord.append(&newCh, 1);
							word.append(&newCh, 1);
						}
						else {
							throw new Exception("unknown symbol after \\, use double \\");
						}						
						continue;						
					}
					else {

						// token \x11

						if (pos >= text.getSize() - 2)
							throw new Exception("\\x at the end of file");

						char hexNumber[3];
						hexNumber[0] = text[pos + 1];
						hexNumber[1] = text[pos + 2];
						hexNumber[2] = 0;
						UInt n;
						if (sscanf(hexNumber, "%2x", &n) != 1)
							throw new Exception("incorrect \\x token");
						if (n == 0) {
							throw new Exception("incorrect \\x token : 0 is not accepted");
						}
						newCh = (char)n;
						word.append(&newCh, 1);
						nextWord.append(&newCh, 1);
						pos += 2;
						continue;
					}
            }
				else {

					if (!quotes && text[pos] == '\'') apos = !apos;
					if (!apos && text[pos] == '"') quotes = !quotes;
				}

				// appends the symbol to the word
				word.append(!symbolReplacement, symbolReplacement.len());
         }						
      }

		if (!word.size()) {
      
			// empty word (only comments)

			continue; // will reread word
		}	

		// the , will be filtered
		if (word == ",") {
						
			word = "";
			nextWord = "";
			continue;
		}

		break;
	}
	while (true);
	}//try
	catch (OutOfBufferBorders* e) {
		delete e;

      if (apos || quotes) {
			// not unquote
			throw new Exception("end of string not found (e.g. symbol ' or \")");
		}

      if (com2) {
			// not unquote
			throw new Exception("end of comment */ not found");
		}

		if (failOnEmptyWord && word.size() == 0)
			throw new Exception("expected some word, but no more text");
	}

	return word;
}

void rev_order(void* num,int size) {

	int i;
	u_char* t = new u_char[size];

	for (i = 0; i < size; i++ )
			*(t + (size - 1 - i) )=*((u_char*)num + i);

	memcpy(num,t,size);

	delete[] t;
}


void readHexNumber(const char* numberString, DefSize requiedSize, DBuffer& numberBuffer) {
	
	int hexsize;

	if ((hexsize = BaseType :: is_hex(numberString)) == 0) {

		throw new Exception("given '%s', but expected hex number",numberString);		
	}

	unsigned int num;
	int size = 0;
	int i = 0;

	if (numberString[0] == '0' && numberString[1] == 'x') {

		i += 2;
		hexsize -= 2;
	}

	if (hexsize % 2 != 0) { 

		if (hexsize > 5) {

			throw new Exception("given '%s', but number of digits must be even",numberString);			
		}

		if (!sscanf(numberString + i,"%1x",&num)) Test();
		if (num || (hexsize == 1) ) {
							
			numberBuffer.setByte(0, (u_char)num);
			size++;
		}  
		else if (!num) hexsize--;
		i++;
	}
		
	while (size < (hexsize + 1)/2) {
		
		if (!sscanf(numberString + i,"%2x",&num)) Test();					
					
		numberBuffer.setByte(size,(u_char)num);

		size++;
		i+=2;
	}
}


void IPv4AddressType :: read_ip_address(const char* string, u_int* address) {

	hostent* h;

   h = gethostbyname(string);	

	if (!h)
		throw new Exception("%s - incorrect IP address",(char*) string);	   

	memcpy(address, (u_char*)(*h).h_addr_list[0], 4);	
}


